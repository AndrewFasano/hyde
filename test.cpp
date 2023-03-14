#include <coroutine>
#include <exception>
#include <iostream>
#include <assert.h>

// Structure based on upon https://www.scs.stanford.edu/~dm/blog/c++-coroutines.html, the only
// good example of coroutines on internet.
struct ReturnObject4 {
  struct promise_type {
    unsigned value_;

    ReturnObject4 get_return_object() {
      return {
        .h_ = std::coroutine_handle<promise_type>::from_promise(*this)
      };
    }
    std::suspend_never initial_suspend() { return {}; }

     /* Must be suspend_always, otherwise other_counter will be destroyed
     automatically and we can't see that it's done
     */
    std::suspend_always final_suspend() noexcept { return {}; }

    void unhandled_exception() {}
    std::suspend_always yield_value(unsigned value) {
      value_ = value;
      return {};
    }
    void return_void() { }
  };

  std::coroutine_handle<promise_type> h_;
};

ReturnObject4 other_counter() {
    for (unsigned i = 100; i < 105; i++) {
        printf("\t\tOther_counter yields %d\n", i);
        co_yield i;
    }
    co_return;
}

ReturnObject4 main_counter() {
    /* In python this would look something like:
    while (i += 1):
        if i == 3:
            yield_from other_counter()
        yield i
    */
    for (unsigned i = 0;; ++i) {
        if (i == 3) {
            printf("\tBegin yield_from\n");
            auto h = other_counter().h_;
            auto &promise = h.promise();
            while (!h.done()) {
                co_yield promise.value_;
                h(); // Advance the other coroutine
            }
            h.destroy();
            printf("\tAll done with yield_from\n");
        }
        printf("\tmain_counter yields %d\n", i);
        co_yield i;
    }
}

int main() {
    auto h = main_counter().h_;
    auto &promise = h.promise();
    for (int i = 0; i < 10; ++i) {
        std::cout << "main[" << i << "] =>" << promise.value_ << std::endl;
        if (i == 9) break; // Don't advance coroutine after our last print
        h();
    }
    h.destroy();
    return 0;
}