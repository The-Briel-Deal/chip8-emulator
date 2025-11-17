#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "raylib.h"

#define DISPLAY_WIDTH 64
#define DISPLAY_HEIGHT 32

#define WINDOW_WIDTH 1280
#define WINDOW_HEIGHT 640

#define PIXEL_WIDTH WINDOW_WIDTH / DISPLAY_WIDTH
#define PIXEL_HEIGHT WINDOW_HEIGHT / DISPLAY_HEIGHT

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

  // TODO: This is a single color for each pixel so we don't need 8 bits
  uint8_t display[DISPLAY_WIDTH][DISPLAY_HEIGHT];
  uint16_t pc;
  uint16_t stack[16];
  uint8_t heap[4096];
};

void init_state(struct state *state);
int main_loop(struct state *state);

int main() {
  InitWindow(WINDOW_WIDTH, WINDOW_HEIGHT,
             "raylib [core] example - basic window");
  struct state state;
  init_state(&state);
  main_loop(&state);
}

void init_state(struct state *state) {
  state->running = true;
  memset(state->display, 0, sizeof(state->display));
}

void draw_grid(uint8_t display[DISPLAY_WIDTH][DISPLAY_HEIGHT]);
uint16_t *fetch(uint8_t heap[4096], uint16_t pc);
struct inst decode(uint16_t inst);
// TODO: This isn't right
uint16_t execute(uint16_t pc);

int main_loop(struct state *state) {
  while (!WindowShouldClose()) {
    // uint16_t *inst = fetch(state->heap, state->pc);
    draw_grid(state->display);
  }
  return 0;
}

void draw_grid(uint8_t display[DISPLAY_WIDTH][DISPLAY_HEIGHT]) {
  BeginDrawing();
  ClearBackground(BLACK);
  for (int y = 0; y < DISPLAY_HEIGHT; y++) {
    for (int x = 0; x < DISPLAY_WIDTH; x++) {
      if (display[x][y])
        DrawRectangle(x * PIXEL_WIDTH, y * PIXEL_HEIGHT, PIXEL_WIDTH,
                      PIXEL_HEIGHT, RAYWHITE);
    }
  }
  EndDrawing();
}

uint16_t *fetch(uint8_t heap[4096], uint16_t pc) {
  return (uint16_t *)&heap[pc++];
}
