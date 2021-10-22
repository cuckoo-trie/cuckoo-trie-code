#define unlikely(cond) __builtin_expect(!!(cond), 0)
#define likely(cond) __builtin_expect(!!(cond), 1)

#define UNUSED_PARAMETER(param) (void) (param)
