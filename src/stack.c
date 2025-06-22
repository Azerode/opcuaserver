#include "../include/stack.h"

#define GROW_CAPACITY(capacity) \
    ((capacity) < 8 ? 8 : (capacity) * 2)

#define GROW_ARRAY(type, pointer, newCount) \
    (type*)reallocate(pointer, \
        sizeof(type) * (newCount))

// Private functions (static)
// In the case where we cannot manage functions in order in the file
static void* reallocate(void* pointer, size_t new_size);


/// @brief Create a stack.
/// @param capacity The maximum number of elements the stack can hold.
/// @return A pointer to the created stack.
////// @note The stack must be destroyed using `destroy_stack` to free allocated memory.
Stack *create_stack(){
    Stack* stack = (Stack*)malloc(sizeof(Stack));
    stack->count = 0;
    stack->capacity = 0;
    stack->data = NULL;

    return stack;
}

/// @brief Destroy a stack.
/// @param stack A pointer to the stack to destroy.
/// @note This function frees the memory allocated for the stack.
void destroy_stack(Stack *stack){
    if (!stack) return;
    
    if(stack->data != NULL) {
        free(stack->data);
    }

    free(stack);
}

/// @brief Check if the stack is empty.
/// @param stack A pointer to the stack to check.
/// @return 1 if the stack is empty, 0 otherwise.
/// @note This function does not modify the stack.
bool is_empty(Stack *stack){
    return stack->count == 0;
}

/// @brief Check if the stack is full.
/// @param stack A pointer to the stack to check.
/// @return 1 if the stack is full, 0 otherwise.
/// @note This function does not modify the stack.
bool is_full(Stack *stack){
    return stack->count == stack->capacity;
}

/// @brief Push a value onto the stack.
/// @param stack A pointer to the stack to push the value onto.
/// @param value The value to push onto the stack.
void stack_push(Stack *stack, char* value){
    if(stack->capacity < stack->count + 1) {
        stack->capacity = GROW_CAPACITY(stack->capacity);
        stack->data = GROW_ARRAY(char*, stack->data, stack->capacity);
    }

    stack->data[stack->count++] = value;
}

/// @brief Pop a value from the stack.
/// @param stack A pointer to the stack to pop the value from.
/// @return The value popped from the stack.
/// @note The caller is responsible for freeing the memory of the popped value if it was dynamically allocated.
char* stack_pop(Stack *stack){
    char* value;

    if(is_empty(stack)) {
        return NULL;
    }

    stack->count --;
    value = stack->data[stack->count];
    stack->data[stack->count] = NULL; // Clear the popped value

    return value;
}

/// @brief Peek at the top value of the stack without removing it.
/// @param stack A pointer to the stack to peek at.
/// @return The top value of the stack.
/// @note This function does not modify the stack. If the stack is empty, it may return NULL or an error value.
char* stack_peek(Stack *stack){
    if(is_empty(stack)) {
        return NULL;
    }

    return stack->data[stack->count -1];
}

/// @brief Reallocate memory for a pointer.
/// @param pointer The pointer to reallocate.
/// @param oldSize The old size of the memory block.
/// @param newSize The new size of the memory block.
/// @return A pointer to the reallocated memory block, or NULL if the allocation failed.
/// @note This function is used internally by the stack implementation to manage memory.
static void* reallocate(void* pointer, size_t new_size){
    if(new_size == 0) {
        free(pointer);
        return NULL;
    }
    void* result = realloc(pointer, new_size);

    return result;
}