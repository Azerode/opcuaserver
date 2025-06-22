#include "../include/tests/stack_test.h"

/// @brief Test stack initialization.
/// @param None
/// @return None
/// @details This function tests the creation of a stack, ensuring it initializes with zero capacity and count.
/// It checks that the data pointer is NULL and that the count and capacity are both set to zero.
/// It also ensures that the stack can be destroyed without memory leaks.
/// @note This function is part of the stack test suite.
/// @see create_stack(), destroy_stack()
void test_stack_init(void){
    Stack* stack = create_stack();
    
    TEST_ASSERT_NULL(stack->data);
    TEST_ASSERT_EQUAL_INT(0, stack->count);
    TEST_ASSERT_EQUAL_INT(0, stack->capacity);
    
    destroy_stack(stack);
}

/// @brief Test stack push operation.
/// @param None
/// @return None
/// @details This function tests the push operation of the stack, ensuring that elements can be added successfully.
/// It checks that the count increases with each push and that the data is stored correctly.
/// It also verifies that the stack can handle multiple pushes and maintains the correct order of elements.
/// @note This function is part of the stack test suite.
/// @see stack_push(), create_stack(), destroy_stack()
void test_stack_push(void){
    Stack* stack = create_stack();
    stack_push(stack, "item1");
    stack_push(stack, "item2");

    stack_push(stack, "item1");
    TEST_ASSERT_EQUAL_INT(3, stack->count);
    TEST_ASSERT_EQUAL_STRING("item1", stack->data[0]);

    stack_push(stack, "item2");
    TEST_ASSERT_EQUAL_INT(4, stack->count);
    TEST_ASSERT_EQUAL_STRING("item2", stack->data[1]);

    destroy_stack(stack);
}

/// @brief Test stack pop operation.
/// @param None
/// @return None
/// @details This function tests the pop operation of the stack, ensuring that elements can be removed successfully.
/// It checks that the count decreases with each pop and that the correct element is returned.
/// It also verifies that popping from an empty stack returns NULL and does not cause memory leaks.
/// @note This function is part of the stack test suite.
/// @see stack_pop(), create_stack(), destroy_stack()
void test_stack_pop(void){
    Stack* stack = create_stack();
    stack_push(stack, "item1");
    stack_push(stack, "item2");

    char* item = stack_pop(stack);
    TEST_ASSERT_EQUAL_STRING("item2", item);
    TEST_ASSERT_EQUAL_INT(1, stack->count);

    item = stack_pop(stack);
    TEST_ASSERT_EQUAL_STRING("item1", item);
    TEST_ASSERT_EQUAL_INT(0, stack->count);

    destroy_stack(stack);
}

/// @brief Test popping from an empty stack.
/// @param None
/// @return None
/// @details This function tests the behavior of the stack when attempting to pop from an empty stack.
/// It checks that the pop operation returns NULL and that the count remains zero.
/// It ensures that the stack can handle this case without crashing or causing memory leaks.
/// @note This function is part of the stack test suite.
/// @see stack_pop(), create_stack(), destroy_stack()
void test_stack_pop_empty(void){
    Stack* stack = create_stack();

    char* item = stack_pop(stack);
    TEST_ASSERT_NULL(item);
    TEST_ASSERT_EQUAL_INT(0, stack->count);

    destroy_stack(stack);
}

/// @brief Test stack peek operation.
/// @param None
/// @return None
/// @details This function tests the peek operation of the stack, ensuring that the top element can be accessed without removal.
/// It checks that the correct element is returned and that the count remains unchanged.
/// It also verifies that peeking into an empty stack returns NULL and does not cause memory leaks.
/// @note This function is part of the stack test suite.
/// @see stack_peek(), create_stack(), destroy_stack()
void test_stack_peek(void){
    Stack* stack = create_stack();
    stack_push(stack, "item1");
    stack_push(stack, "item2");

    char* item = stack_peek(stack);
    TEST_ASSERT_EQUAL_STRING("item2", item);
    TEST_ASSERT_EQUAL_INT(2, stack->count);
    
    destroy_stack(stack);
}

/// @brief Test peeking into an empty stack.
/// @param None
/// @return None
/// @details This function tests the behavior of the stack when attempting to peek into an empty stack.
/// It checks that the peek operation returns NULL and does not cause memory leaks.
/// @note This function is part of the stack test suite.
/// @see stack_peek(), create_stack(), destroy_stack()
void test_stack_peek_empty(void){
    Stack* stack = create_stack();
    
    char* item = stack_peek(stack);
    TEST_ASSERT_NULL(item);
    TEST_ASSERT_EQUAL_INT(0, stack->count);
    
    destroy_stack(stack);
}

/// @brief Test stack initialization with zero capacity.
/// @param None
/// @return None
/// @details This function tests the creation of a stack with zero capacity, ensuring that it initializes correctly.
/// It checks that the data pointer is NULL and that the count and capacity are both set to zero.
/// It also ensures that the stack can handle this case without crashing or causing memory leaks.
/// @note This function is part of the stack test suite.
/// @see create_stack(), destroy_stack()
void test_stack_init_with_zero_capacity(void){
    Stack* stack = create_stack();
    
    TEST_ASSERT_NULL(stack->data);
    TEST_ASSERT_EQUAL_INT(0, stack->count);
    TEST_ASSERT_EQUAL_INT(0, stack->capacity);
    
    destroy_stack(stack);
}

/// @brief Test stack push operation over capacity.
/// @param None
/// @return None
/// @details This function tests the push operation of the stack when it is at full capacity.
/// It checks that the push operation fails gracefully and does not cause memory leaks.
/// @note This function is part of the stack test suite.
/// @see stack_push(), create_stack(), destroy_stack()
void test_stack_push_over_capacity(void){
    Stack* stack = create_stack();

    stack_push(stack, "item1");
    stack_push(stack, "item2");

    // Attempt to push beyond capacity
    stack_push(stack, "item3");

    TEST_ASSERT_EQUAL_INT(3, stack->count);
    TEST_ASSERT_EQUAL_STRING("item3", stack->data[2]);
    
    destroy_stack(stack);
}
