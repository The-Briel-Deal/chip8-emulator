#include <stdbool.h>
#include <stdint.h>

#include "raylib.h"

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
  InitWindow(800, 450, "raylib [core] example - basic window");
  struct state state;
  init_state(&state);
  main_loop(&state);
}

void init_state(struct state *state) { state->running = true; }

uint16_t *fetch(uint8_t heap[4096], uint16_t pc);
struct inst decode(uint16_t inst);
// TODO: This isn't right
uint16_t execute(uint16_t pc);

int main_loop(struct state *state) {
  while (!WindowShouldClose()) {
    // uint16_t *inst = fetch(state->heap, state->pc);
    BeginDrawing();
    ClearBackground(RAYWHITE);
    DrawText("Congrats! You created your first window!", 190, 200, 20,
             LIGHTGRAY);
    EndDrawing();
  }
  return 0;
}

uint16_t *fetch(uint8_t heap[4096], uint16_t pc) {
  return (uint16_t *)&heap[pc++];
}
