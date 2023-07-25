#include <stdio.h>
#include <windows.h>

// Dummy function pointer to use for VirtualProtect demo
void* dummyFunction = (void*)malloc;

// Function to try allocating RWX memory
void rwxOperations() {
    DWORD oldProtection;

    // Let's try to allocate some RWX memory
    void* mem = VirtualAlloc(0, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) {
        printf(" |--- [-] Error allocating RWX memory\n");
    }
    else {
        printf(" |--- [+] RWX memory allocated: %p\n", mem);
    }

    // Let's also try a VirtualProtect to see if we can update an existing page to RWX
    if (!VirtualProtect(dummyFunction, 4096, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        printf(" |--- [-] Error updating dummyFunction [%p] memory to RWX\n\n", dummyFunction);
    }
    else {
        printf(" |--- [+] dummyFunction [%p] memory updated to RWX\n\n", dummyFunction);
    }
}

int main(void) {
  
    int c;

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy;
    ZeroMemory(&policy, sizeof(policy));
    policy.ProhibitDynamicCode = 1;

    printf("Program started\n---------------\n");

    // Allocate and set RWX memory
    printf("[*] Press a key to allocate and set RWX memory...\n");
    c = getchar();
    rwxOperations();

    printf("[*] Press a key to run SetProcessMitigationPolicy to apply PROCESS_MITIGATION_DYNAMIC_CODE_POLICY...\n");
    c = getchar();

    // Set the dynamic code policy to prohibit dynamic code
    if (SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)) == false) {
        printf(" |--- [-] SetProcessMitigationPolicy failed\n");
        return 1; // Return 1 on failure
    }
    else {
        printf(" |--- [+] Process mitigation policy set\n\n");
    }

    printf("[*] Press a key to allocate and set RWX memory again (should fail due to the dynamic code policy)...\n");
    c = getchar();

    // Allocate and set RWX memory again (should fail due to the dynamic code policy)
    rwxOperations();

    return 0; // Return 0 on success
}