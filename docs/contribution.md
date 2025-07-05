# C Naming Convention Documentation

## Overview
Consistent naming conventions in C improve code readability, maintainability, and collaboration. This document outlines standard naming rules for variables, constants, functions, types, and macros in C projects.

1. Variable Names
- Use lowercase letters.
- Separate words with underscores (`snake_case`).
- Names should be descriptive and meaningful.

Examples:
`count`, `total_sum`, `buffer_size`

2. Constant Names
- Use all uppercase letters.
- Separate words with underscores.
- Prefix with k or CONST_ is optional but can clarify intent.

Examples:
`MAX_LENGTH`, `PI`, `BUFFER_SIZE`

3. Function Names
- Use lowercase letters.
- Separate words with underscores.
- Use verbs to indicate actions.

Examples:
`read_file()`, `calculate_average()`, `print_result()`

4. Type Names (struct, enum, typedef)
- Use CamelCase (capitalize each word).
- Avoid underscores.

Examples:
`Person`, `LinkedList`, `FileStatus`

5. Macro Names
- Use all uppercase letters.
- Separate words with underscores.

Examples:
`DEBUG_MODE`, `MIN`, `ARRAY_SIZE`

6. General Guidelines
- Do not start names with a digit.
- Avoid using reserved keywords.
- Use descriptive names; avoid single-letter names except for loop counters.
- Be consistent throughout the codebase.

Example
```c
#define MAX_SIZE 100

typedef struct Person {
    char name[50];
    int age;
} Person;

int calculate_average(int total, int count);

int main() {
    int total_sum = 0;
    int count = 10;
    int average = calculate_average(total_sum, count);
    return 0;
}
```