#include <stdbool.h>
#include <stdint.h>

struct inst {
  enum tag {
    CLEAR,
    JUMP,
    SET,
    ADD,
    SET_INDEX,
  } tag;
};

struct state {
  bool running;

  uint16_t pc;
  uint16_t stack[16];
  uint8_t heap[4096];
};

void init_state(struct state *state);
int main_loop(struct state *state);

int main() {
  struct state state;
  init_state(&state);
  main_loop(&state);
}

void init_state(struct state *state) { state->running = true; }

uint16_t fetch(uint16_t pc);
uint16_t decode(uint16_t inst);
uint16_t execute(uint16_t pc);

int main_loop(struct state *state) {}
