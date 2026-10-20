#include "agl_policy.h"
#include "agl_context.h"
#include "agl_util.h"
#include "agl_event.h"
#include "AgentLensProtocol/agl_policy.h"

#define AGL_MAX_POLICY_RULES 128

typedef struct _AGL_POLICY_ENTRY {
    ULONG EventType;
    ULONG Action;
    ULONG RuleSet;
    ULONG Priority;
    ULONG AccessMask;
    ULONG ImageHash;
    ULONG UserSidHash;
    ULONG RootProcessHash;
    ULONG PathLength;
    ULONG ProcessLength;
    ULONG CommandLineLength;
    PWCHAR Path;
    PWCHAR Process;
    PWCHAR CommandLine;
} AGL_POLICY_ENTRY;

typedef struct _AGL_POLICY_TRIE_RULE_REF {
    ULONG RuleIndex;
    ULONG Next;
} AGL_POLICY_TRIE_RULE_REF;

typedef struct _AGL_POLICY_TRIE_NODE {
    WCHAR Character;
    ULONG FirstChild;
    ULONG NextSibling;
    ULONG RuleHead;
} AGL_POLICY_TRIE_NODE;

typedef struct _AGL_POLICY_TRIE {
    AGL_POLICY_TRIE_NODE* Nodes;
    ULONG NodeCount;
    ULONG NodeCapacity;
    AGL_POLICY_TRIE_RULE_REF* RuleRefs;
    ULONG RuleRefCount;
    ULONG RuleRefCapacity;
} AGL_POLICY_TRIE;

typedef struct _AGL_POLICY_SNAPSHOT {
    volatile LONG RefCount;
    AGL_POLICY_ENTRY Rules[AGL_MAX_POLICY_RULES];
    ULONG Count;
    ULONG Mode;
    ULONG EventStart[AGL_EVENT_MAX];
    ULONG EventCount[AGL_EVENT_MAX];
    AGL_POLICY_TRIE PathTrie;
} AGL_POLICY_SNAPSHOT;

static KSPIN_LOCK AglPolicyLock;
static AGL_POLICY_SNAPSHOT* AglActivePolicy = NULL;

static BOOLEAN AglPolicyRuleLess(AGL_POLICY_ENTRY* A, AGL_POLICY_ENTRY* B);

static PWCHAR AglPolicyCopyString(const WCHAR* Source, ULONG Bytes)
{
    PWCHAR buffer;

    if (!Source || Bytes == 0)
    {
        return NULL;
    }

    buffer = (PWCHAR)AglAllocNonPaged(Bytes + sizeof(WCHAR));
    if (!buffer)
    {
        return NULL;
    }

    RtlCopyMemory(buffer, Source, Bytes);
    buffer[Bytes / sizeof(WCHAR)] = L'\0';
    return buffer;
}

static void AglPolicyFreeEntry(AGL_POLICY_ENTRY* Entry)
{
    if (Entry->Path)
    {
        AglFree(Entry->Path);
        Entry->Path = NULL;
    }
    if (Entry->Process)
    {
        AglFree(Entry->Process);
        Entry->Process = NULL;
    }
    if (Entry->CommandLine)
    {
        AglFree(Entry->CommandLine);
        Entry->CommandLine = NULL;
    }
}

static void AglPolicySortRules(AGL_POLICY_SNAPSHOT* Snapshot)
{
    ULONG i;

    for (i = 1; i < Snapshot->Count; i++)
    {
        AGL_POLICY_ENTRY key = Snapshot->Rules[i];
        LONG j = (LONG)i - 1;

        while (j >= 0 && AglPolicyRuleLess(&Snapshot->Rules[j], &key))
        {
            Snapshot->Rules[j + 1] = Snapshot->Rules[j];
            j--;
        }
        Snapshot->Rules[j + 1] = key;
    }
}

static BOOLEAN AglPolicyRuleLess(AGL_POLICY_ENTRY* A, AGL_POLICY_ENTRY* B)
{
    if (A->EventType != B->EventType) return A->EventType > B->EventType;
    if (A->Priority != B->Priority) return A->Priority < B->Priority;
    return A->PathLength < B->PathLength;
}

static void AglPolicyTrieFree(AGL_POLICY_TRIE* Trie)
{
    if (!Trie)
    {
        return;
    }

    if (Trie->Nodes)
    {
        AglFree(Trie->Nodes);
    }
    if (Trie->RuleRefs)
    {
        AglFree(Trie->RuleRefs);
    }
    RtlZeroMemory(Trie, sizeof(*Trie));
}

static void AglPolicyFreeSnapshot(AGL_POLICY_SNAPSHOT* Snapshot)
{
    ULONG i;

    if (!Snapshot)
    {
        return;
    }

    for (i = 0; i < Snapshot->Count; i++)
    {
        AglPolicyFreeEntry(&Snapshot->Rules[i]);
    }
    AglPolicyTrieFree(&Snapshot->PathTrie);
    AglFree(Snapshot);
}

static AGL_POLICY_SNAPSHOT* AglPolicyPublishSnapshot(
    AGL_POLICY_SNAPSHOT* NewSnapshot)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    AGL_POLICY_SNAPSHOT* oldSnapshot;

    KeAcquireInStackQueuedSpinLock(&AglPolicyLock, &lockHandle);
    oldSnapshot = AglActivePolicy;
    AglActivePolicy = NewSnapshot;
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    return oldSnapshot;
}

static AGL_POLICY_SNAPSHOT* AglPolicyAcquireSnapshot(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    AGL_POLICY_SNAPSHOT* snapshot;

    KeAcquireInStackQueuedSpinLock(&AglPolicyLock, &lockHandle);
    snapshot = AglActivePolicy;
    if (snapshot)
    {
        InterlockedIncrement(&snapshot->RefCount);
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return snapshot;
}

static void AglPolicyReleaseSnapshot(AGL_POLICY_SNAPSHOT* Snapshot)
{
    if (!Snapshot)
    {
        return;
    }

    if (InterlockedDecrement(&Snapshot->RefCount) == 0)
    {
        AglPolicyFreeSnapshot(Snapshot);
    }
}

static BOOLEAN AglPolicyTrieEnsureNodeCapacity(AGL_POLICY_TRIE* Trie, ULONG Needed)
{
    AGL_POLICY_TRIE_NODE* newNodes;
    ULONG newCapacity;

    if (Trie->NodeCapacity >= Needed)
    {
        return TRUE;
    }

    newCapacity = Trie->NodeCapacity ? Trie->NodeCapacity : 256;
    while (newCapacity < Needed)
    {
        newCapacity *= 2;
    }

    newNodes = (AGL_POLICY_TRIE_NODE*)AglAllocNonPaged(
        newCapacity * sizeof(AGL_POLICY_TRIE_NODE));
    if (!newNodes)
    {
        return FALSE;
    }

    RtlZeroMemory(newNodes, newCapacity * sizeof(AGL_POLICY_TRIE_NODE));
    if (Trie->NodeCount)
    {
        RtlCopyMemory(
            newNodes,
            Trie->Nodes,
            Trie->NodeCount * sizeof(AGL_POLICY_TRIE_NODE));
    }

    if (Trie->Nodes)
    {
        AglFree(Trie->Nodes);
    }
    Trie->Nodes = newNodes;
    Trie->NodeCapacity = newCapacity;
    return TRUE;
}

static BOOLEAN AglPolicyTrieEnsureRuleRefCapacity(AGL_POLICY_TRIE* Trie, ULONG Needed)
{
    AGL_POLICY_TRIE_RULE_REF* newRefs;
    ULONG newCapacity;

    if (Trie->RuleRefCapacity >= Needed)
    {
        return TRUE;
    }

    newCapacity = Trie->RuleRefCapacity ? Trie->RuleRefCapacity : 128;
    while (newCapacity < Needed)
    {
        newCapacity *= 2;
    }

    newRefs = (AGL_POLICY_TRIE_RULE_REF*)AglAllocNonPaged(
        newCapacity * sizeof(AGL_POLICY_TRIE_RULE_REF));
    if (!newRefs)
    {
        return FALSE;
    }

    RtlZeroMemory(newRefs, newCapacity * sizeof(AGL_POLICY_TRIE_RULE_REF));
    if (Trie->RuleRefCount)
    {
        RtlCopyMemory(
            newRefs,
            Trie->RuleRefs,
            Trie->RuleRefCount * sizeof(AGL_POLICY_TRIE_RULE_REF));
    }

    if (Trie->RuleRefs)
    {
        AglFree(Trie->RuleRefs);
    }
    Trie->RuleRefs = newRefs;
    Trie->RuleRefCapacity = newCapacity;
    return TRUE;
}

static WCHAR AglPolicyFoldChar(WCHAR Char)
{
    if (Char >= L'a' && Char <= L'z')
    {
        return (WCHAR)(Char - L'a' + L'A');
    }
    return Char;
}

static ULONG AglPolicyTrieFindChild(
    AGL_POLICY_TRIE* Trie,
    ULONG ParentIndex,
    WCHAR Character)
{
    ULONG childIndex;

    if (!Trie->Nodes || ParentIndex >= Trie->NodeCount)
    {
        return (ULONG)-1;
    }

    childIndex = Trie->Nodes[ParentIndex].FirstChild;
    while (childIndex != (ULONG)-1)
    {
        if (Trie->Nodes[childIndex].Character == Character)
        {
            return childIndex;
        }
        childIndex = Trie->Nodes[childIndex].NextSibling;
    }
    return (ULONG)-1;
}

static ULONG AglPolicyTrieAddNode(AGL_POLICY_TRIE* Trie, ULONG ParentIndex, WCHAR Character)
{
    ULONG newIndex;

    if (!AglPolicyTrieEnsureNodeCapacity(Trie, Trie->NodeCount + 1))
    {
        return (ULONG)-1;
    }

    newIndex = Trie->NodeCount++;
    RtlZeroMemory(&Trie->Nodes[newIndex], sizeof(Trie->Nodes[newIndex]));
    Trie->Nodes[newIndex].Character = Character;
    Trie->Nodes[newIndex].FirstChild = (ULONG)-1;
    Trie->Nodes[newIndex].NextSibling = (ULONG)-1;

    if (ParentIndex < Trie->NodeCount)
    {
        ULONG sibling = Trie->Nodes[ParentIndex].FirstChild;
        if (sibling == (ULONG)-1)
        {
            Trie->Nodes[ParentIndex].FirstChild = newIndex;
        }
        else
        {
            while (Trie->Nodes[sibling].NextSibling != (ULONG)-1)
            {
                sibling = Trie->Nodes[sibling].NextSibling;
            }
            Trie->Nodes[sibling].NextSibling = newIndex;
        }
    }

    return newIndex;
}

static ULONG AglPolicyTrieGetOrAddChild(
    AGL_POLICY_TRIE* Trie,
    ULONG ParentIndex,
    WCHAR Character)
{
    ULONG childIndex = AglPolicyTrieFindChild(Trie, ParentIndex, Character);
    if (childIndex != (ULONG)-1)
    {
        return childIndex;
    }
    return AglPolicyTrieAddNode(Trie, ParentIndex, Character);
}

static BOOLEAN AglPolicyTrieAddRuleIndex(
    AGL_POLICY_TRIE* Trie,
    ULONG NodeIndex,
    ULONG RuleIndex)
{
    AGL_POLICY_TRIE_NODE* node;
    ULONG refIndex;

    if (!Trie->Nodes || NodeIndex >= Trie->NodeCount)
    {
        return FALSE;
    }

    node = &Trie->Nodes[NodeIndex];
    refIndex = node->RuleHead;
    while (refIndex != (ULONG)-1)
    {
        if (Trie->RuleRefs[refIndex].RuleIndex == RuleIndex)
        {
            return TRUE;
        }
        refIndex = Trie->RuleRefs[refIndex].Next;
    }

    if (!AglPolicyTrieEnsureRuleRefCapacity(Trie, Trie->RuleRefCount + 1))
    {
        return FALSE;
    }

    refIndex = Trie->RuleRefCount++;
    Trie->RuleRefs[refIndex].RuleIndex = RuleIndex;
    Trie->RuleRefs[refIndex].Next = node->RuleHead;
    node->RuleHead = refIndex;
    return TRUE;
}

static BOOLEAN AglPolicyTrieInsert(
    AGL_POLICY_TRIE* Trie,
    AGL_POLICY_ENTRY* Rule,
    ULONG RuleIndex)
{
    ULONG nodeIndex = 0;
    ULONG i;

    if (!Rule || !Trie)
    {
        return FALSE;
    }

    if (Rule->PathLength == 0)
    {
        return AglPolicyTrieAddRuleIndex(Trie, 0, RuleIndex);
    }

    for (i = 0; i < Rule->PathLength; i++)
    {
        WCHAR folded = AglPolicyFoldChar(Rule->Path[i]);
        nodeIndex = AglPolicyTrieGetOrAddChild(Trie, nodeIndex, folded);
        if (nodeIndex == (ULONG)-1)
        {
            return FALSE;
        }
    }

    return AglPolicyTrieAddRuleIndex(Trie, nodeIndex, RuleIndex);
}

static BOOLEAN AglPolicyBuildTrie(AGL_POLICY_SNAPSHOT* Snapshot)
{
    AGL_POLICY_TRIE* trie = &Snapshot->PathTrie;
    ULONG i;

    AglPolicyTrieFree(trie);

    if (!AglPolicyTrieEnsureNodeCapacity(trie, 1))
    {
        return FALSE;
    }
    RtlZeroMemory(&trie->Nodes[0], sizeof(trie->Nodes[0]));
    trie->Nodes[0].FirstChild = (ULONG)-1;
    trie->Nodes[0].NextSibling = (ULONG)-1;
    trie->NodeCount = 1;

    if (!AglPolicyTrieEnsureRuleRefCapacity(trie, 1))
    {
        AglPolicyTrieFree(trie);
        return FALSE;
    }

    for (i = 0; i < Snapshot->Count; i++)
    {
        if (!AglPolicyTrieInsert(trie, &Snapshot->Rules[i], i))
        {
            AglPolicyTrieFree(trie);
            return FALSE;
        }
    }

    return TRUE;
}

static ULONG AglPolicyCollectTrieCandidates(
    AGL_POLICY_TRIE* Trie,
    PCUNICODE_STRING Path,
    ULONG* Candidates,
    ULONG CandidateCapacity)
{
    ULONG candidateCount = 0;
    ULONG nodeIndex = 0;
    ULONG i;

    if (!Trie || !Trie->Nodes || !Trie->RuleRefs || !Candidates || CandidateCapacity == 0)
    {
        return 0;
    }

    if (Trie->Nodes[0].RuleHead != (ULONG)-1)
    {
        ULONG refIndex = Trie->Nodes[0].RuleHead;
        while (refIndex != (ULONG)-1)
        {
            if (candidateCount >= CandidateCapacity)
            {
                return candidateCount;
            }
            Candidates[candidateCount++] = Trie->RuleRefs[refIndex].RuleIndex;
            refIndex = Trie->RuleRefs[refIndex].Next;
        }
    }

    if (!Path || !Path->Buffer || Path->Length == 0)
    {
        return candidateCount;
    }

    for (i = 0; i < Path->Length / sizeof(WCHAR); i++)
    {
        WCHAR folded = AglPolicyFoldChar(Path->Buffer[i]);
        ULONG childIndex = AglPolicyTrieFindChild(Trie, nodeIndex, folded);
        if (childIndex == (ULONG)-1)
        {
            break;
        }

        nodeIndex = childIndex;
        if (Trie->Nodes[nodeIndex].RuleHead != (ULONG)-1)
        {
            ULONG refIndex = Trie->Nodes[nodeIndex].RuleHead;
            while (refIndex != (ULONG)-1)
            {
                if (candidateCount >= CandidateCapacity)
                {
                    return candidateCount;
                }
                Candidates[candidateCount++] = Trie->RuleRefs[refIndex].RuleIndex;
                refIndex = Trie->RuleRefs[refIndex].Next;
            }
        }
    }

    return candidateCount;
}

static void AglPolicySortCandidates(
    AGL_POLICY_SNAPSHOT* Snapshot,
    ULONG* Candidates,
    ULONG CandidateCount)
{
    ULONG i;
    for (i = 1; i < CandidateCount; i++)
    {
        ULONG key = Candidates[i];
        LONG j = (LONG)i - 1;
        while (j >= 0 &&
               (Snapshot->Rules[Candidates[j]].Priority < Snapshot->Rules[key].Priority ||
                (Snapshot->Rules[Candidates[j]].Priority == Snapshot->Rules[key].Priority &&
                 Snapshot->Rules[Candidates[j]].PathLength < Snapshot->Rules[key].PathLength)))
        {
            Candidates[j + 1] = Candidates[j];
            j--;
        }
        Candidates[j + 1] = key;
    }
}

static void AglRebuildEventIndex(AGL_POLICY_SNAPSHOT* Snapshot)
{
    ULONG i;
    RtlZeroMemory(Snapshot->EventStart, sizeof(Snapshot->EventStart));
    RtlZeroMemory(Snapshot->EventCount, sizeof(Snapshot->EventCount));

    for (i = 0; i < Snapshot->Count; i++)
    {
        ULONG type = Snapshot->Rules[i].EventType;
        if (type < AGL_EVENT_MAX)
        {
            Snapshot->EventCount[type]++;
        }
    }

    ULONG offset = 0;
    for (i = 0; i < AGL_EVENT_MAX; i++)
    {
        Snapshot->EventStart[i] = offset;
        offset += Snapshot->EventCount[i];
    }
}

static BOOLEAN AglMatchString(
    PCWSTR Pattern,
    ULONG PatternLength,
    PCUNICODE_STRING Value)
{
    UNICODE_STRING pattern;

    if (!PatternLength || !Value || !Value->Buffer || Value->Length == 0)
    {
        return FALSE;
    }

    pattern.Buffer = (PWCH)Pattern;
    pattern.Length = (USHORT)(PatternLength * sizeof(WCHAR));
    pattern.MaximumLength = pattern.Length;
    return RtlPrefixUnicodeString(&pattern, Value, TRUE);
}

static ULONG AglHashUnicodeString(PCUNICODE_STRING Value)
{
    ULONG hash = 5381;
    if (!Value || !Value->Buffer)
    {
        return 0;
    }
    for (ULONG i = 0; i < Value->Length / sizeof(WCHAR); i++)
    {
        hash = hash * 33 + Value->Buffer[i];
    }
    return hash;
}

NTSTATUS AglPolicyInitialize(void)
{
    KeInitializeSpinLock(&AglPolicyLock);
    AglActivePolicy = NULL;
    return STATUS_SUCCESS;
}

void AglPolicyUninitialize(void)
{
    AGL_POLICY_SNAPSHOT* oldSnapshot = AglPolicyPublishSnapshot(NULL);
    AglPolicyReleaseSnapshot(oldSnapshot);
}

NTSTATUS AglPolicyLoad(PVOID Policy, ULONG PolicyLength)
{
    AGL_POLICY_HEADER* header;
    PUCHAR cursor;
    ULONG remaining;
    ULONG i;
    AGL_POLICY_SNAPSHOT* snapshot = NULL;
    AGL_POLICY_SNAPSHOT* oldSnapshot = NULL;

    if (!Policy || PolicyLength < sizeof(AGL_POLICY_HEADER))
    {
        return STATUS_INVALID_PARAMETER;
    }

    header = (AGL_POLICY_HEADER*)Policy;
    if (header->StructSize < sizeof(*header) || header->Version != AGL_PROTOCOL_VERSION)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->StructSize > PolicyLength)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->RuleCount > AGL_MAX_POLICY_RULES)
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    snapshot = (AGL_POLICY_SNAPSHOT*)AglAllocNonPaged(sizeof(*snapshot));
    if (!snapshot)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    snapshot->RefCount = 1;

    cursor = (PUCHAR)Policy + header->StructSize;
    remaining = PolicyLength - header->StructSize;

    for (i = 0; i < header->RuleCount; i++)
    {
        AGL_POLICY_RULE* rule;
        AGL_POLICY_ENTRY* entry;
        ULONG pathBytes;
        ULONG processBytes;
        ULONG commandBytes;

        if (remaining < sizeof(AGL_POLICY_RULE))
        {
            AglPolicyFreeSnapshot(snapshot);
            return STATUS_INVALID_PARAMETER;
        }

        rule = (AGL_POLICY_RULE*)cursor;
        pathBytes = rule->PathLength;
        processBytes = rule->ProcessLength;
        commandBytes = rule->CommandLineLength;

        if (pathBytes > (AGL_MAX_PATH_CHARS - 1) * sizeof(WCHAR) ||
            processBytes > (AGL_MAX_PATH_CHARS - 1) * sizeof(WCHAR) ||
            commandBytes > (AGL_MAX_PATH_CHARS - 1) * sizeof(WCHAR))
        {
            AglPolicyFreeSnapshot(snapshot);
            return STATUS_INVALID_PARAMETER;
        }

        if (((pathBytes | processBytes | commandBytes) & 1) != 0)
        {
            AglPolicyFreeSnapshot(snapshot);
            return STATUS_INVALID_PARAMETER;
        }

        if (remaining < sizeof(AGL_POLICY_RULE) + pathBytes + processBytes + commandBytes)
        {
            AglPolicyFreeSnapshot(snapshot);
            return STATUS_INVALID_PARAMETER;
        }

        entry = &snapshot->Rules[i];
        RtlZeroMemory(entry, sizeof(*entry));
        snapshot->Count = i + 1;
        entry->EventType = rule->EventType;
        entry->Action = rule->Action;
        entry->RuleSet = rule->RuleSet;
        entry->Priority = rule->Priority;
        entry->AccessMask = rule->AccessMask;
        entry->ImageHash = rule->ImageHash;
        entry->UserSidHash = rule->UserSidHash;
        entry->RootProcessHash = rule->RootProcessHash;
        entry->PathLength = pathBytes / sizeof(WCHAR);
        entry->ProcessLength = processBytes / sizeof(WCHAR);
        entry->CommandLineLength = commandBytes / sizeof(WCHAR);

        entry->Path = AglPolicyCopyString((const WCHAR*)rule->Data, pathBytes);
        entry->Process = AglPolicyCopyString(
            (const WCHAR*)((PUCHAR)rule->Data + pathBytes),
            processBytes);
        entry->CommandLine = AglPolicyCopyString(
            (const WCHAR*)((PUCHAR)rule->Data + pathBytes + processBytes),
            commandBytes);
        if ((pathBytes && !entry->Path) ||
            (processBytes && !entry->Process) ||
            (commandBytes && !entry->CommandLine))
        {
            AglPolicyFreeSnapshot(snapshot);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        cursor += sizeof(AGL_POLICY_RULE) + pathBytes + processBytes + commandBytes;
        remaining -= sizeof(AGL_POLICY_RULE) + pathBytes + processBytes + commandBytes;
    }

    snapshot->Mode = header->Mode;
    AglPolicySortRules(snapshot);
    AglRebuildEventIndex(snapshot);

    if (!AglPolicyBuildTrie(snapshot))
    {
        AglPolicyFreeSnapshot(snapshot);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    oldSnapshot = AglPolicyPublishSnapshot(snapshot);
    AglPolicyReleaseSnapshot(oldSnapshot);
    return STATUS_SUCCESS;
}

void AglPolicyClear(void)
{
    AGL_POLICY_SNAPSHOT* oldSnapshot = AglPolicyPublishSnapshot(NULL);
    AglPolicyReleaseSnapshot(oldSnapshot);
}

BOOLEAN AglPolicyShouldDenyEx(ULONG EventType, PCUNICODE_STRING Path, ULONG AccessMask)
{
    BOOLEAN deny = FALSE;
    AGL_PROCESS_CTX* processCtx = NULL;
    AGL_PROCESS_CTX* rootCtx = NULL;
    UNICODE_STRING processPath = { 0 };
    UNICODE_STRING commandLine = { 0 };
    ULONG rootProcessHash = 0;
    ULONG candidates[AGL_MAX_POLICY_RULES];
    ULONG candidateCount;
    ULONG candidateIndex;
    AGL_POLICY_SNAPSHOT* snapshot;

    processCtx = AglContextAcquireProcess((ULONG64)(ULONG_PTR)PsGetCurrentProcessId());
    if (processCtx)
    {
        processPath = processCtx->ImagePath;
        commandLine = processCtx->CommandLine;
        rootCtx = AglContextAcquireRootByAgentSessionId(processCtx->AgentSessionId);
        if (rootCtx)
        {
            rootProcessHash = AglHashUnicodeString(&rootCtx->ImagePath);
        }
    }

    snapshot = AglPolicyAcquireSnapshot();
    if (!snapshot || snapshot->Mode != AGL_POLICY_MODE_CONTROL)
    {
        AglPolicyReleaseSnapshot(snapshot);
        if (rootCtx) AglContextReleaseProcess(rootCtx);
        if (processCtx) AglContextReleaseProcess(processCtx);
        return FALSE;
    }

    candidateCount = AglPolicyCollectTrieCandidates(
        &snapshot->PathTrie,
        Path,
        candidates,
        ARRAYSIZE(candidates));
    AglPolicySortCandidates(snapshot, candidates, candidateCount);

    for (candidateIndex = 0; candidateIndex < candidateCount; candidateIndex++)
    {
        AGL_POLICY_ENTRY* entry = &snapshot->Rules[candidates[candidateIndex]];
        if (entry->EventType != EventType)
        {
            continue;
        }

        if (entry->ProcessLength &&
            !AglMatchString(entry->Process, entry->ProcessLength, &processPath))
        {
            continue;
        }

        if (entry->ImageHash &&
            AglHashUnicodeString(&processPath) != entry->ImageHash)
        {
            continue;
        }

        if (entry->UserSidHash &&
            processCtx &&
            processCtx->TokenSidHash != entry->UserSidHash)
        {
            continue;
        }

        if (entry->RootProcessHash &&
            (!rootCtx || rootProcessHash != entry->RootProcessHash))
        {
            continue;
        }

        if (entry->CommandLineLength &&
            !AglMatchString(entry->CommandLine, entry->CommandLineLength, &commandLine))
        {
            continue;
        }

        if (entry->AccessMask &&
            (entry->AccessMask & AccessMask) == 0)
        {
            continue;
        }

        if (entry->Action == 1)
        {
            deny = TRUE;
        }
        break;
    }

    AglPolicyReleaseSnapshot(snapshot);
    if (rootCtx)
    {
        AglContextReleaseProcess(rootCtx);
    }
    if (processCtx)
    {
        AglContextReleaseProcess(processCtx);
    }
    return deny;
}

BOOLEAN AglPolicyShouldDeny(ULONG EventType, PCUNICODE_STRING Path)
{
    return AglPolicyShouldDenyEx(EventType, Path, 0);
}
