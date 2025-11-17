#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "raylib.h"

#define DISPLAY_WIDTH 64
#define DISPLAY_HEIGHT 32

#define WINDOW_WIDTH 1280
#define WINDOW_HEIGHT 640

#define PIXEL_WIDTH WINDOW_WIDTH / DISPLAY_WIDTH
#define PIXEL_HEIGHT WINDOW_HEIGHT / DISPLAY_HEIGHT

#define PROG_START 0x200

typedef uint64_t display[DISPLAY_HEIGHT];

enum run_mode {
  UNSET = 0,
  EXECUTE,
  DISASSEMBLE,
};

// For instructions with 0x_XNN
struct reg_val {
  uint8_t reg; // X
  uint8_t val; // NN
};

struct __attribute__((packed)) inst {
  enum inst_tag : uint16_t {
    CLEAR,
    JUMP,
    SET,
    ADD,
    SET_IDX,
    DISPLAY,
  } tag;
  union inst_data {
    // JUMP - 0x1NNN
    uint16_t jump; // NNN
    // SET - 0x6XNN
    struct reg_val set; // reg = X, val = NN
    // ADD - 0x7XNN
    struct reg_val add; // reg = X, val = NN
    // SET_IDX - 0xANNN
    uint16_t set_idx; // NNN
    // DISPLAY - 0xDXYN
    struct __attribute__((packed)) display_data {
      u_int reg_x : 4;  // X
      u_int reg_y : 4;  // Y
      u_int height : 4; // N
    } display;
  } data;
};

struct state {
  bool running;

  // TODO: This is a single color for each pixel so we don't need 8 bits
  display display;
  uint16_t pc;
  uint16_t stack[16];
  uint8_t heap[4096];
};

int execute_entry(char *filename);
int disassemble_entry(char *filename);

int main(int argc, char **argv) {

  enum run_mode run_mode = UNSET;

  int c;
  char *filename = NULL;

  while ((c = getopt(argc, argv, "edf:")) != -1)
    switch (c) {
    case 'e':
      if (run_mode != UNSET) {
        fprintf(stderr,
                "Option `e` and `d` specified, these are mutually exclusive\n");
        return 1;
      }
      run_mode = EXECUTE;
      break;
    case 'd':
      if (run_mode != UNSET) {
        fprintf(stderr,
                "Option `e` and `d` specified, these are mutually exclusive\n");
        return 1;
      }
      run_mode = DISASSEMBLE;
      break;
    case 'f':
      filename = optarg;
      break;
    case '?':
      if (optopt == 'f')
        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
      else if (isprint(optopt))
        fprintf(stderr, "Unknown option `-%c'.\n", optopt);
      else
        fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
      return 1;
    default:
      abort();
    }

  switch (run_mode) {
  case EXECUTE:
    return execute_entry(filename);
  case DISASSEMBLE:
    return disassemble_entry(filename);
  case UNSET:
    fprintf(stderr, "Run Mode unset, please specify either `-e` to execute or "
                    "`-d` to disassemble.\n");
    return 1;
  }
}

void init_state(struct state *state);
int main_loop(struct state *state);

int execute_entry(char *filename) {
  InitWindow(WINDOW_WIDTH, WINDOW_HEIGHT,
             "raylib [core] example - basic window");
  struct state state;
  init_state(&state);
  state.display[3] = 32;
  return main_loop(&state);
}

void init_state(struct state *state) {
  state->running = true;
  state->pc = PROG_START;
  memset(state->display, 0, sizeof(state->display));
}

uint16_t fetch(uint8_t heap[4096], uint16_t pc);
struct inst decode(uint16_t inst);
void execute(struct inst inst);

void draw_grid(display display);

int main_loop(struct state *state) {
  while (!WindowShouldClose()) {
    uint16_t raw_inst = fetch(state->heap, state->pc);
    struct inst inst = decode(raw_inst);
    draw_grid(state->display);
  }
  return 0;
}

void draw_grid(display display) {
  BeginDrawing();
  ClearBackground(BLACK);
  for (int y = 0; y < DISPLAY_HEIGHT; y++) {
    for (int x = 0; x < DISPLAY_WIDTH; x++) {
      uint64_t row = display[y];
      if (row & ((uint64_t)(1) << x))
        DrawRectangle(x * PIXEL_WIDTH, y * PIXEL_HEIGHT, PIXEL_WIDTH,
                      PIXEL_HEIGHT, RAYWHITE);
    }
  }
  EndDrawing();
}

uint16_t fetch(uint8_t heap[4096], uint16_t pc) {
  return *(uint16_t *)&heap[pc++];
}

#define NIBBLE1(inst) (inst & 0xF000) >> 12
#define NIBBLE2(inst) (inst & 0x0F00) >> 8
#define NIBBLE3(inst) (inst & 0x00F0) >> 4
#define NIBBLE4(inst) (inst & 0x000F) >> 0
#define LOWER8(inst) (inst & 0x00FF) >> 0
#define LOWER12(inst) (inst & 0x0FFF) >> 0

struct inst decode(uint16_t inst) {
  switch (NIBBLE1(inst)) {
  case 0x0:
    if (inst == 0x00E0)
      return (struct inst){.tag = CLEAR};
    break;
  case 0x1:
    // JUMP - Jump is the only instruction that starts with 0x1
    return (struct inst){.tag = JUMP, .data = {.jump = LOWER12(inst)}};
  case 0x6:
    // SET - 0x6XNN set reg vX to NN
    return (struct inst){
        .tag = SET,
        .data = {.set = {.reg = NIBBLE2(inst), .val = LOWER8(inst)}}};
  case 0x7:
    // ADD - 0x7XNN add NN to reg vX
    return (struct inst){
        .tag = ADD,
        .data = {.add = {.reg = NIBBLE2(inst), .val = LOWER8(inst)}}};
  case 0xA:
    // SET_IDX - 0xANNN set index reg to NNN
    return (struct inst){.tag = SET_IDX, .data = {.set_idx = LOWER12(inst)}};
  case 0xD:
    // DISPLAY - 0xDXYN draw a sprite of height N at the position vX,vY
    return (struct inst){.tag = DISPLAY,
                         .data = {.display = {.reg_x = NIBBLE2(inst),
                                              .reg_y = NIBBLE3(inst),
                                              .height = NIBBLE4(inst)}}};
  }
  printf("Unknown inst of value %x\n", inst);
  exit(1);
}
#undef NIBBLE1
#undef NIBBLE2
#undef NIBBLE3
#undef NIBBLE4
#undef LOWER8
#undef LOWER12

// Code below is for disassembling

int disassemble_entry(char *filename) { printf("filename='%s'\n", filename);
  return 0;
}
