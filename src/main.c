#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
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

#define HEX_CHARS_START 0x0

const uint8_t HEX_CHARS[80];

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
struct reg_reg {
  uint8_t reg1; // X
  uint8_t reg2; // Y
};

struct __attribute__((packed)) inst {
  enum inst_tag : uint16_t {
    UNKNOWN = 0,

    CLEAR,
    RET,
    CALL,
    JUMP,
    JUMP_OFFSET,
    SKIP_IF_EQUAL,
    SKIP_IF_NOT_EQUAL,
    SKIP_IF_REGS_EQUAL,
    SKIP_IF_REGS_NOT_EQUAL,
    SET,
    ADD,
    LOAD_CHAR,
    LOAD_REG_INTO_REG,
    REG_BITWISE_OR,
    REG_BITWISE_AND,
    REG_BITWISE_XOR,
    REG_ADD,
    REG_SUB,
    REG_SUB_N,
    REG_SHIFT_R,
    REG_SHIFT_L,
    SET_IDX,
    RND,
    DISPLAY,
    SKIP_KEY_DOWN,
    SKIP_KEY_UP
  } tag;
  union inst_data {
    uint8_t hex_char;
    uint16_t addr;
    struct reg_val reg_val;
    struct reg_reg reg_reg;

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
  uint8_t stack_top;
  uint16_t index_reg;
  uint8_t regs[16];
  uint8_t heap[4096];
};

int execute_entry(const char *filename);
int disassemble_entry(const char *filename);

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
    case 'f': filename = optarg; break;
    case '?':
      if (optopt == 'f')
        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
      else if (isprint(optopt))
        fprintf(stderr, "Unknown option `-%c'.\n", optopt);
      else
        fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
      return 1;
    default: abort();
    }

  switch (run_mode) {
  case EXECUTE: return execute_entry(filename);
  case DISASSEMBLE: return disassemble_entry(filename);
  case UNSET:
    fprintf(stderr, "Run Mode unset, please specify either `-e` to execute or "
                    "`-d` to disassemble.\n");
    return 1;
  }
}

void init_state(struct state *state);
int main_loop(struct state *state);

int execute_entry(const char *filename) {
  InitWindow(WINDOW_WIDTH, WINDOW_HEIGHT,
             "raylib [core] example - basic window");
  struct state state;
  init_state(&state);
  FILE *f = fopen(filename, "r");
  assert(f != NULL);
  size_t bytes_read =
      fread(&state.heap[PROG_START], sizeof(uint8_t), sizeof(state.heap), f);
  assert(bytes_read != 0);
  state.display[3] = 32;
  return main_loop(&state);
}

void init_state(struct state *state) {
  state->running = true;
  state->pc = PROG_START;
  state->stack_top = 0;
  memset(state->display, 0, sizeof(state->display));

  memcpy(&state->heap[HEX_CHARS_START], HEX_CHARS, sizeof(HEX_CHARS));
}

uint16_t fetch(uint8_t heap[4096], uint16_t *pc);
struct inst decode(uint16_t inst);
void execute(struct state *state, struct inst inst);

void draw_grid(display display);

int main_loop(struct state *state) {
  while (!WindowShouldClose()) {
    uint16_t raw_inst = fetch(state->heap, &state->pc);
    struct inst inst = decode(raw_inst);
    execute(state, inst);
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

uint16_t fetch(uint8_t heap[4096], uint16_t *pc) {
  uint8_t byte1 = heap[(*pc)++];
  uint8_t byte2 = heap[(*pc)++];
  return byte1 << 8 | byte2 << 0;
}

#define NIBBLE1(inst) (inst & 0xF000) >> 12
#define NIBBLE2(inst) (inst & 0x0F00) >> 8
#define NIBBLE3(inst) (inst & 0x00F0) >> 4
#define NIBBLE4(inst) (inst & 0x000F) >> 0
#define LOWER8(inst) (inst & 0x00FF) >> 0
#define LOWER12(inst) (inst & 0x0FFF) >> 0

#define VOID_INST(inst_tag)                                                    \
  (struct inst) { .tag = inst_tag }
#define ADDR_INST(inst_tag)                                                    \
  (struct inst) {                                                              \
    .tag = inst_tag, .data = {.addr = LOWER12(inst) }                          \
  }
#define RV_INST(inst_tag)                                                      \
  (struct inst) {                                                              \
    .tag = inst_tag, .data = {                                                 \
      .reg_val = {.reg = NIBBLE2(inst), .val = LOWER8(inst)}                   \
    }                                                                          \
  }
#define RR_INST(inst_tag)                                                      \
  (struct inst) {                                                              \
    .tag = inst_tag, .data = {                                                 \
      .reg_reg = {.reg1 = NIBBLE2(inst), .reg2 = NIBBLE3(inst)},               \
    }                                                                          \
  }
#define CH_INST(inst_tag)                                                      \
  (struct inst) {                                                              \
    .tag = inst_tag, .data = {.hex_char = NIBBLE2(inst) }                      \
  }
#define XYH_INST(inst_tag)                                                     \
  (struct inst) {                                                              \
    .tag = inst_tag, .data = {                                                 \
      .display = {.reg_x = NIBBLE2(inst),                                      \
                  .reg_y = NIBBLE3(inst),                                      \
                  .height = NIBBLE4(inst)}                                     \
    }                                                                          \
  }

struct inst decode(uint16_t inst) {
  switch (NIBBLE1(inst)) {
  case 0x0:
    switch (LOWER8(inst)) {
    case 0xE0: return VOID_INST(CLEAR);
    case 0xEE: return VOID_INST(RET);
    }
    break;
  case 0x1: return ADDR_INST(JUMP);
  case 0x2: return ADDR_INST(CALL);
  case 0x3: return RV_INST(SKIP_IF_EQUAL);
  case 0x4: return RV_INST(SKIP_IF_NOT_EQUAL);
  case 0x5: return RR_INST(SKIP_IF_REGS_EQUAL);
  case 0x6: return RV_INST(SET);
  case 0x7: return RV_INST(ADD);
  case 0x8:
    switch (NIBBLE4(inst)) {
    case 0x0: return RR_INST(LOAD_REG_INTO_REG);
    case 0x1: return RR_INST(REG_BITWISE_OR);
    case 0x2: return RR_INST(REG_BITWISE_AND);
    case 0x3: return RR_INST(REG_BITWISE_XOR);
    case 0x4: return RR_INST(REG_ADD);
    case 0x5: return RR_INST(REG_SUB);
    case 0x6: return RR_INST(REG_SHIFT_R);
    case 0xE: return RR_INST(REG_SHIFT_L);
    case 0x7: return RR_INST(REG_SUB_N);
    }
    break;
  case 0x9: return RR_INST(SKIP_IF_REGS_NOT_EQUAL);
  case 0xA: return ADDR_INST(SET_IDX);
  case 0xB: return ADDR_INST(JUMP_OFFSET);
  case 0xC: return RV_INST(RND);
  case 0xD: return XYH_INST(DISPLAY);
  case 0xE:
    switch (LOWER8(inst)) {
    case 0x9E: return CH_INST(SKIP_KEY_DOWN);
    case 0xA1: return CH_INST(SKIP_KEY_UP);
    }
    break;
  case 0xF:
    switch (LOWER8(inst)) {
    case 0x29: return CH_INST(LOAD_CHAR);
    }
    break;
  }
  return VOID_INST(UNKNOWN);
}
#undef NIBBLE1
#undef NIBBLE2
#undef NIBBLE3
#undef NIBBLE4
#undef LOWER8
#undef LOWER12

#define REVERSE_BYTE(byte)                                                     \
  {                                                                            \
    byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;                            \
    byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;                            \
    byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;                            \
  }
#define PUSH(val) state->stack[++state->stack_top] = val

void disassemble_inst(struct inst inst);
void execute(struct state *state, struct inst inst) {
#ifdef DEBUG_DISASM
  disassemble_inst(inst);
#endif
  switch (inst.tag) {
  case CLEAR: memset(state->display, 0, sizeof(state->display)); break;
  case RET:
    assert(state->stack_top > 0);
    uint16_t return_addr = state->stack[state->stack_top--];
    state->pc = return_addr;
    break;
  case CALL: {
    uint16_t call_addr = inst.data.addr;
    uint16_t ret_addr = state->pc;
    PUSH(ret_addr);
    state->pc = call_addr;
  }
  case JUMP: state->pc = inst.data.addr; break;
  case SET: state->regs[inst.data.reg_val.reg] = inst.data.reg_val.val; break;
  case ADD: state->regs[inst.data.reg_val.reg] += inst.data.reg_val.val; break;
  case SET_IDX: state->index_reg = inst.data.addr; break;
  case LOAD_CHAR: {
    uint8_t hex_char = state->regs[inst.data.hex_char];
    state->index_reg = HEX_CHARS_START + (5 * hex_char);
    break;
  }
  case DISPLAY: {
    uint8_t x_pos = state->regs[inst.data.display.reg_x];
    uint8_t y_pos = state->regs[inst.data.display.reg_y];
    uint8_t height = inst.data.display.height;

    // If no bits are turned off set VF to 0
    state->regs[0xF] = 0;
    for (int i = 0; i < height; i++) {
      uint8_t line = state->heap[state->index_reg + i];
      REVERSE_BYTE(line);
      uint64_t *display_line = &state->display[y_pos + i];

      // If this turns any bits off set VF to 1
      if (*display_line & (((uint64_t)line) << x_pos)) state->regs[0xF] = 1;

      *display_line ^= (((uint64_t)line) << x_pos);
    }
    break;
  }
  case UNKNOWN: assert(false); break;
  default: assert(false); break;
  }
}

// Code below is for disassembling
void disassemble_inst(struct inst inst) {
  switch (inst.tag) {
  case CLEAR: printf("CLEAR"); break;
  case RET: printf("RET"); break;
  case CALL: printf("CALL 0x%04x", inst.data.addr); break;
  case JUMP: printf("JUMP 0x%04x", inst.data.addr); break;
  case SET:
    printf("SET v%x to 0x%02x", inst.data.reg_val.reg, inst.data.reg_val.val);
    break;
  case ADD:
    printf("ADD v%x += %d", inst.data.reg_val.reg, inst.data.reg_val.val);
    break;
  case SET_IDX: printf("SET_IDX 0x%03x", inst.data.addr); break;
  case LOAD_CHAR: printf("LOAD_CHAR v%x", inst.data.hex_char); break;
  case DISPLAY:
    printf("DISPLAY v%x,v%x height=%d", inst.data.display.reg_x,
           inst.data.display.reg_y, inst.data.display.height);
    break;
  case UNKNOWN: printf("UNKNOWN"); break;
  }

  printf("\n");
}

int disassemble_entry(const char *filename) {
  printf("Disassembling filename='%s'\n", filename);
  FILE *f = fopen(filename, "r");
  assert(f != NULL);
  uint8_t buf[4096];
  size_t bytes_read = fread(&buf[PROG_START], sizeof(uint8_t), sizeof(buf), f);
  assert(bytes_read != 0);

  uint16_t pc = PROG_START;

  while (pc < bytes_read + PROG_START) {
    uint16_t raw_inst = fetch(buf, &pc);
    printf("pc=0x%04x ri=0x%04x ", pc, raw_inst);
    struct inst inst = decode(raw_inst);
    disassemble_inst(inst);
  }
  return 0;
}

const uint8_t HEX_CHARS[80] = {
    /* clang-format off */
    0b11110000,
    0b10010000,
    0b10010000,
    0b10010000,
    0b11110000,

    0b00100000,
    0b01100000,
    0b00100000,
    0b00100000,
    0b01110000,

    0b11110000,
    0b00010000,
    0b11110000,
    0b10000000,
    0b11110000,

    0b11110000,
    0b00010000,
    0b11110000,
    0b00010000,
    0b11110000,

    0b10010000,
    0b10010000,
    0b11110000,
    0b00010000,
    0b00010000,

    0b11110000,
    0b10000000,
    0b11110000,
    0b00010000,
    0b11110000,

    0b11110000,
    0b10000000,
    0b11110000,
    0b10010000,
    0b11110000,

    0b11110000,
    0b00010000,
    0b00100000,
    0b01000000,
    0b01000000,

    0b11110000,
    0b10010000,
    0b11110000,
    0b10010000,
    0b11110000,

    0b11110000,
    0b10010000,
    0b11110000,
    0b00010000,
    0b11110000,

    0b11110000,
    0b10010000,
    0b11110000,
    0b10010000,
    0b10010000,

    0b11100000,
    0b10010000,
    0b11100000,
    0b10010000,
    0b11100000,

    0b11110000,
    0b10000000,
    0b10000000,
    0b10000000,
    0b11110000,

    0b11100000,
    0b10010000,
    0b10010000,
    0b10010000,
    0b11100000,

    0b11110000,
    0b10000000,
    0b11110000,
    0b10000000,
    0b11110000,

    0b11110000,
    0b10000000,
    0b11110000,
    0b10000000,
    0b10000000,
    /* clang-format on */
};
