


# 🐍 Broken Python — Privilege Drop Bypass in SUID Application

## Challenge Overview

The challenge involves a **SUID C application embedding a Python interpreter**.  
The program is supposed to drop elevated privileges before executing user-supplied Python code.

However, the original implementation allows a user-controlled flag (`--no_drop`) to bypass the privilege-dropping logic, resulting in a **critical privilege escalation vulnerability**.

---

## Vulnerability Summary

### Root Cause

- The application trusts a user-supplied flag to decide whether privileges are dropped.
- Privileges are dropped incorrectly (only Effective UID).
- The **Saved UID (suid)** remains intact.
- Because Python is embedded, an attacker can regain root privileges using:
  ```python
  os.setuid(0)
````
````
### Impact

* Full privilege escalation
* Arbitrary code execution as root
* Complete compromise of the system

---

## The Correct Fix (“The Right Touch”)

To securely handle privileges in a SUID binary:

* Privileges **must be dropped unconditionally**
* **Real, Effective, and Saved UIDs must all be cleared**
* This is achieved using:

  ```c
  setresuid(ruid, ruid, ruid);
  ```

This ensures privilege dropping is **permanent and irreversible**.

---

## Fixed Source Code (Secure Version)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <Python.h>

void execute_python_code(const char *code) {
    PyObject *main_module, *main_dict;
    PyObject *result;
    
    main_module = PyImport_AddModule("__main__");
    main_dict = PyModule_GetDict(main_module);
    
    result = PyRun_String(code, Py_single_input, main_dict, main_dict);
    
    if (result == NULL) {
        PyErr_Print();
    } else {
        Py_DECREF(result);
    }
}

void interactive_repl() {
    char line[1024];
    PyObject *main_module, *main_dict;
    PyObject *result;
    
    main_module = PyImport_AddModule("__main__");
    main_dict = PyModule_GetDict(main_module);
    
    printf("Python %s REPL (Embedded in C)\n", Py_GetVersion());
    printf("Type 'exit()' or 'quit()' or press Ctrl+D to exit.\n");
    printf(">>> ");
    fflush(stdout);
    
    while (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\n")] = 0;
        
        if (strcmp(line, "exit()") == 0 || 
            strcmp(line, "quit()") == 0 || 
            strcmp(line, "exit") == 0 || 
            strcmp(line, "quit") == 0) {
            break;
        }
        
        if (strlen(line) == 0) {
            printf(">>> ");
            fflush(stdout);
            continue;
        }
        
        result = PyRun_String(line, Py_single_input, main_dict, main_dict);
        
        if (result == NULL) {
            PyErr_Print();
        } else {
            Py_DECREF(result);
        }
        
        printf(">>> ");
        fflush(stdout);
    }
    
    printf("\nExiting Python REPL.\n");
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] [python_code]\n", prog_name);
    printf("Options:\n");
    printf("  --no_drop    Do not drop SUID privileges\n");
    printf("  --help       Show this help message\n");
}

int main(int argc, char *argv[]) {
    uid_t ruid, euid, suid;
    const char *python_code = NULL;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--no_drop") == 0) {
            // Flag is intentionally ignored for security reasons
            continue;
        } else {
            python_code = argv[i];
        }
    }
    
    // Get current UIDs (Real, Effective, Saved)
    if (getresuid(&ruid, &euid, &suid) == -1) {
        perror("getresuid failed");
        exit(1);
    }
    
    printf("Real UID: %d\n", ruid);
    printf("Effective UID: %d\n", euid);
    
    /*
     * THE "RIGHT TOUCH" FIX:
     * Drop Real, Effective, and Saved UID permanently.
     * This prevents privilege re-escalation from Python.
     */
    if (setresuid(ruid, ruid, ruid) == -1) {
        perror("setresuid failed");
        exit(1);
    }
    
    printf("Privileges dropped permanently. Running as UID: %d\n", getuid());

    Py_Initialize();
    
    if (!Py_IsInitialized()) {
        fprintf(stderr, "Failed to initialize Python interpreter\n");
        exit(1);
    }
    
    if (python_code != NULL) {
        execute_python_code(python_code);
    } else {
        interactive_repl();
    }
    
    Py_Finalize();
    
    return 0;
}
```

---

## Why This Works

* `setresuid()` clears **Real, Effective, and Saved UID**
* `--no_drop` can no longer bypass security
* Python can no longer regain elevated privileges
* `os.getresuid()` returns identical unprivileged UIDs
* The validator confirms the fix and accepts the solution

---

## Key Lessons

* Never trust user input for security decisions
* Dropping only `euid` is **insufficient**
* Embedded interpreters magnify privilege bugs
* `setresuid()` is the only safe approach for SUID binaries

---

🏁 **Broken Python fixed. Validator passed. Flag captured.**



---
