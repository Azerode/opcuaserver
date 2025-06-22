#ifndef STACK_H
#define STACK_H

#include "common.h"

/// @brief Header file for a simple stack implementation in C
/// @file stack.h
typedef struct {
    int count;
    int capacity;
    char** data;
} Stack;

/// @brief Create a stack.
/// @param capacity The maximum number of elements the stack can hold.
/// @return A pointer to the created stack.
////// @note The stack must be destroyed using `destroy_stack` to free allocated memory.
Stack *create_stack();

/// @brief Destroy a stack.
/// @param stack A pointer to the stack to destroy.
/// @note This function frees the memory allocated for the stack.
void destroy_stack(Stack *stack);

/// @brief Check if the stack is empty.
/// @param stack A pointer to the stack to check.
/// @return 1 if the stack is empty, 0 otherwise.
/// @note This function does not modify the stack.
bool is_empty(Stack *stack);

/// @brief Check if the stack is full.
/// @param stack A pointer to the stack to check.
/// @return 1 if the stack is full, 0 otherwise.
/// @note This function does not modify the stack.
bool is_full(Stack *stack);

/// @brief Push a value onto the stack.
/// @param stack A pointer to the stack to push the value onto.
/// @param value The value to push onto the stack.
void stack_push(Stack *stack, char* value);

/// @brief Pop a value from the stack.
/// @param stack A pointer to the stack to pop the value from.
/// @return The value popped from the stack.
/// @note The caller is responsible for freeing the memory of the popped value if it was dynamically allocated.
char* stack_pop(Stack *stack);

/// @brief Peek at the top value of the stack without removing it.
/// @param stack A pointer to the stack to peek at.
/// @return The top value of the stack.
/// @note This function does not modify the stack. If the stack is empty, it may return NULL or an error value.
char* stack_peek(Stack *stack);

#endif // STACK_H