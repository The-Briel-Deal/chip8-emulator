#include <assert.h>
#include <bits/time.h>
#include <ctype.h>
#include <math.h>
#include <pulse/simple.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pulse/context.h>
#include <pulse/def.h>
#include <pulse/error.h>
#include <pulse/mainloop-api.h>
#include <pulse/mainloop.h>
#include <pulse/sample.h>
#include <pulse/stream.h>

#include <raylib.h>

#define DISPLAY_WIDTH 64
#define DISPLAY_HEIGHT 32

#define WINDOW_WIDTH 1280
#define WINDOW_HEIGHT 640

#define PIXEL_WIDTH WINDOW_WIDTH / DISPLAY_WIDTH
#define PIXEL_HEIGHT WINDOW_HEIGHT / DISPLAY_HEIGHT

#define PROG_START 0x200

#define HEX_CHARS_START 0x0

#define TICKS_PER_SEC 60
#define MICROS_PER_SEC 1 * 1000 * 1000
#define MICROS_PER_TICK MICROS_PER_SEC / TICKS_PER_SEC

#define DEFAULT_RATE 44100
#define DEFAULT_CHANNELS 2
#define DEFAULT_VOLUME 0.7

#define M_PI_M2 (M_PI + M_PI)

#define C_4_PITCH 261.63
#define AUDIO_BUFSIZE 1024 * 10

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
  uint8_t vx;
  uint8_t vy;
};
struct __attribute__((packed)) display_data {
  u_int vx : 4;     // X
  u_int vy : 4;     // Y
  u_int height : 4; // N
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
    SKIP_KEY_UP,
    LOAD_DELAY_TIMER,
    LOAD_KEY_PRESS,
    SET_DELAY_TIMER,
    SET_SOUND_TIMER,
    ADD_INDEX,
    LOAD_BCD,
    STORE_REGS,
    LOAD_REGS,
  } tag;
  union inst_data {
    uint8_t reg;
    uint16_t addr;
    struct reg_val reg_val;
    struct reg_reg reg_reg;
    struct display_data display;
  } data;
};

struct state {
  bool running;

  display display;
  uint16_t pc;
  uint16_t stack[16];
  uint8_t stack_top;
  uint16_t index_reg;
  uint8_t regs[16];
  uint8_t heap[4096];

  uint8_t delay_timer;
  uint8_t sound_timer;

  pa_mainloop *pa_mainloop;
  pa_context *pa_context;
  pa_stream *pa_stream;
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

double accum = 0;
static const pa_sample_spec PA_SAMPLE_SPEC = {.format = PA_SAMPLE_S16LE,
                                              .rate = DEFAULT_RATE,
                                              .channels = DEFAULT_CHANNELS};
static const pa_buffer_attr PA_BUFFER_ATTR = {
    .fragsize = (uint32_t)-1,
    .maxlength = (uint32_t)-1,
    .minreq = (uint32_t)-1,
    .prebuf = (uint32_t)-1,
    .tlength = (uint32_t)-1,
};
// I think this will be more than enough but I put assert below just in case.
uint8_t buf[1024 * 1024];
void pa_write_callback(pa_stream *p, size_t nbytes, void *userdata) {
  assert(nbytes < sizeof(buf));
  int frame_size = pa_frame_size(&PA_SAMPLE_SPEC);

  for (int i = 0; i < nbytes;) {
    accum += M_PI_M2 * C_4_PITCH / DEFAULT_RATE;
    if (accum >= M_PI_M2) accum -= M_PI_M2;
    int16_t val = sin(accum) * DEFAULT_VOLUME * 32767.0;
    *(uint16_t *)(&buf[i]) = val;
    *(uint16_t *)(&buf[i + 2]) = val;

    i += frame_size;
  }

  pa_stream_write(p, buf, nbytes, NULL, 0, PA_SEEK_RELATIVE);
}

void pa_state_cb(pa_context *c, void *userdata) {
  struct state *state = userdata;

  pa_context_state_t pa_state = pa_context_get_state(c);
  switch (pa_state) {
  case PA_CONTEXT_FAILED:
  case PA_CONTEXT_TERMINATED: exit(1);
  case PA_CONTEXT_READY: {
    state->pa_stream = pa_stream_new(state->pa_context, "chip8 emulator audio",
                                     &PA_SAMPLE_SPEC, NULL);
    pa_stream_set_write_callback(state->pa_stream, pa_write_callback, NULL);

    int r = pa_stream_connect_playback(
        state->pa_stream, NULL, &PA_BUFFER_ATTR,
        PA_STREAM_START_CORKED | PA_STREAM_AUTO_TIMING_UPDATE |
            PA_STREAM_ADJUST_LATENCY | PA_STREAM_AUTO_TIMING_UPDATE,
        NULL, NULL);
    if (r != 0)
      printf("Error from pa_stream_connect_playback(): %s\n", pa_strerror(r));
    break;
  }
  default: break;
  }
}

void init_pulseaudio(struct state *state) {
  // this is initialized in pa_state_cb once the context is ready
  state->pa_stream = NULL;

  // TODO: Free all of these objects
  state->pa_mainloop = pa_mainloop_new();
  pa_mainloop_api *pa_mainloop_api = pa_mainloop_get_api(state->pa_mainloop);

  state->pa_context = pa_context_new(pa_mainloop_api, "chip8 emulator");
  pa_context_set_state_callback(state->pa_context, pa_state_cb, state);
  pa_context_connect(state->pa_context, NULL, 0, NULL);
}

void init_state(struct state *state) {
  state->running = true;
  state->pc = PROG_START;
  state->stack_top = 0;
  state->delay_timer = 0;
  state->sound_timer = 0;
  memset(state->display, 0, sizeof(state->display));
  memcpy(&state->heap[HEX_CHARS_START], HEX_CHARS, sizeof(HEX_CHARS));

  init_pulseaudio(state);
}

uint64_t get_time_micro() {
  struct timespec time;
  int e;
  e = clock_gettime(CLOCK_MONOTONIC, &time);
  assert(e == 0);

  uint64_t res = 0;
  res += time.tv_nsec / 1000;
  res += time.tv_sec * MICROS_PER_SEC;
  return res;
}

void tick(struct state *state) {
  if (state->pa_stream != NULL) {
    if (state->sound_timer > 0 && pa_stream_is_corked(state->pa_stream)) {
      // play
      pa_stream_cork(state->pa_stream, false, NULL, NULL);
    }
    if (state->sound_timer == 0 && !pa_stream_is_corked(state->pa_stream)) {
      // pause
      pa_stream_cork(state->pa_stream, true, NULL, NULL);
    }
  }
  if (state->delay_timer > 0) {
    state->delay_timer -= 1;
  }
  if (state->sound_timer > 0) {
    state->sound_timer -= 1;
  }
}

uint16_t fetch(uint8_t heap[4096], uint16_t *pc);
struct inst decode(uint16_t inst);
void execute(struct state *state, struct inst inst);
void draw_grid(display display);

int main_loop(struct state *state) {
  uint64_t last_tick_micro = get_time_micro();
  uint64_t current_time_micro = last_tick_micro;
  while (!WindowShouldClose()) {
    current_time_micro = get_time_micro();
    if ((current_time_micro - last_tick_micro) > MICROS_PER_TICK) {
      last_tick_micro = current_time_micro;
      tick(state);
    }

    // Audio Start
    pa_mainloop_iterate(state->pa_mainloop, 0, NULL);
    // Audio End

    uint16_t raw_inst = fetch(state->heap, &state->pc);
    struct inst inst = decode(raw_inst);
    execute(state, inst);
    draw_grid(state->display);
  }
  return 0;
}

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
      .reg_reg = {.vx = NIBBLE2(inst), .vy = NIBBLE3(inst)},                   \
    }                                                                          \
  }
#define R_INST(inst_tag)                                                       \
  (struct inst) {                                                              \
    .tag = inst_tag, .data = {                                                 \
      .reg = NIBBLE2(inst),                                                    \
    }                                                                          \
  }
#define XYH_INST(inst_tag)                                                     \
  (struct inst) {                                                              \
    .tag = inst_tag, .data = {                                                 \
      .display = {.vx = NIBBLE2(inst),                                         \
                  .vy = NIBBLE3(inst),                                         \
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
    case 0x9E: return R_INST(SKIP_KEY_DOWN);
    case 0xA1: return R_INST(SKIP_KEY_UP);
    }
    break;
  case 0xF:
    switch (LOWER8(inst)) {
    case 0x07: return R_INST(LOAD_DELAY_TIMER);
    case 0x0A: return R_INST(LOAD_KEY_PRESS);
    case 0x15: return R_INST(SET_DELAY_TIMER);
    case 0x18: return R_INST(SET_SOUND_TIMER);
    case 0x1E: return R_INST(ADD_INDEX);
    case 0x29: return R_INST(LOAD_CHAR); // Maybe this should be R_INST()
    case 0x33: return R_INST(LOAD_BCD);
    case 0x55: return R_INST(STORE_REGS);
    case 0x65: return R_INST(LOAD_REGS);
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
#define POP() state->stack[state->stack_top--]

#define RV(inst) inst.data.reg_val
#define RR(inst) inst.data.reg_reg
#define ADDR(inst) inst.data.addr

#define V(x) state->regs[x]
#define SKIP_IF(condition)                                                     \
  if (condition) state->pc += 2;                                               \
  return

static void ex_ret(struct state *state) {
  assert(state->stack_top > 0);
  uint16_t return_addr = POP();
  state->pc = return_addr;
}
static void ex_call(struct state *state, struct inst inst) {
  uint16_t call_addr = ADDR(inst);
  uint16_t ret_addr = state->pc;
  PUSH(ret_addr);
  state->pc = call_addr;
}
static void ex_load_char(struct state *state, struct inst inst) {
  uint8_t hex_char = state->regs[inst.data.reg];
  assert(hex_char < 0xF);
  state->index_reg = HEX_CHARS_START + (5 * hex_char);
}
static void ex_display(struct state *state, struct inst inst) {
  uint8_t x_pos = V(inst.data.display.vx);
  uint8_t y_pos = V(inst.data.display.vy);
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
}

void disassemble_inst(struct inst inst);
void execute(struct state *state, struct inst inst) {
#ifdef DEBUG_DISASM
  disassemble_inst(inst);
#endif
  switch (inst.tag) {
  case CLEAR: memset(state->display, 0, sizeof(state->display)); return;
  case RET: ex_ret(state); return;
  case CALL: ex_call(state, inst); return;
  case JUMP: state->pc = ADDR(inst); return;
  case JUMP_OFFSET: state->pc = ADDR(inst) + V(0); return;
  case SKIP_IF_EQUAL: SKIP_IF(V(RV(inst).reg) == RV(inst).val);
  case SKIP_IF_NOT_EQUAL: SKIP_IF(V(RV(inst).reg) != RV(inst).val);
  case SKIP_IF_REGS_EQUAL: SKIP_IF(V(RR(inst).vx) == V(RR(inst).vy));
  case SKIP_IF_REGS_NOT_EQUAL: SKIP_IF(V(RR(inst).vx) != V(RR(inst).vy));
  case SET: V(RV(inst).reg) = RV(inst).val; return;
  case ADD: V(RV(inst).reg) += RV(inst).val; return;
  case SET_IDX: state->index_reg = ADDR(inst); return;
  case LOAD_CHAR: ex_load_char(state, inst); return;
  case DISPLAY: ex_display(state, inst); return;
  case LOAD_REG_INTO_REG: V(RR(inst).vx) = V(RR(inst).vy); return;
  case REG_BITWISE_OR: V(RR(inst).vx) |= V(RR(inst).vy); return;
  case REG_BITWISE_AND: V(RR(inst).vx) &= V(RR(inst).vy); return;
  case REG_BITWISE_XOR: V(RR(inst).vx) ^= V(RR(inst).vy); return;
  case REG_ADD: {
    uint16_t sum = V(RR(inst).vx) + V(RR(inst).vy);
    V(RR(inst).vx) = sum & 0xFF;
    V(0xF) = (sum > 255);
    return;
  }
  case REG_SUB: {
    uint8_t flag = V(RR(inst).vx) >= V(RR(inst).vy);
    V(RR(inst).vx) -= V(RR(inst).vy);
    V(0xF) = flag;
    return;
  }
  case REG_SUB_N: {
    uint8_t flag = V(RR(inst).vy) >= V(RR(inst).vx);
    V(RR(inst).vx) = V(RR(inst).vy) - V(RR(inst).vx);
    V(0xF) = flag;
    return;
  }
  case REG_SHIFT_R: {
    // For some old roms I might need to set Vx = Vy
    uint8_t flag = (V(RR(inst).vx) & 0b00000001) != 0;
    V(RR(inst).vx) >>= 1;
    V(0xF) = flag;
    return;
  }
  case REG_SHIFT_L: {
    // For some old roms I might need to set Vx = Vy
    uint8_t flag = (V(RR(inst).vx) & 0b10000000) != 0;
    V(RR(inst).vx) <<= 1;
    V(0xF) = flag;
    return;
  }
  case RND: V(RV(inst).reg) = RV(inst).val & rand(); return;
  case STORE_REGS:
    memcpy(&state->heap[state->index_reg], &state->regs[0], inst.data.reg + 1);
    return;
  case LOAD_REGS:
    memcpy(&state->regs[0], &state->heap[state->index_reg], inst.data.reg + 1);
    return;
  case LOAD_BCD: {
    uint8_t val = V(inst.data.reg);
    state->heap[state->index_reg + 0] = (val / 100) % 10;
    state->heap[state->index_reg + 1] = (val / 10) % 10;
    state->heap[state->index_reg + 2] = (val / 1) % 10;
    return;
  }
  case ADD_INDEX: {
    state->index_reg += V(inst.data.reg);
    return;
  }
  case SKIP_KEY_DOWN:    // TODO: impl
  case SKIP_KEY_UP:      // TODO: impl
  case LOAD_DELAY_TIMER: // TODO: impl
  case LOAD_KEY_PRESS:   // TODO: impl
  case SET_DELAY_TIMER:  // TODO: impl
  case SET_SOUND_TIMER:  // TODO: impl
  case UNKNOWN: assert(false); return;
  }
}

#define PRINT_INST_NAME(inst_name)                                             \
  case inst_name: printf("%-10s", #inst_name); break

// Code below is for disassembling
void disassemble_inst(struct inst inst) {
  switch (inst.tag) {
    PRINT_INST_NAME(UNKNOWN);
    PRINT_INST_NAME(CLEAR);
    PRINT_INST_NAME(RET);
    PRINT_INST_NAME(CALL);
    PRINT_INST_NAME(JUMP);
    PRINT_INST_NAME(JUMP_OFFSET);
    PRINT_INST_NAME(SKIP_IF_EQUAL);
    PRINT_INST_NAME(SKIP_IF_NOT_EQUAL);
    PRINT_INST_NAME(SKIP_IF_REGS_EQUAL);
    PRINT_INST_NAME(SKIP_IF_REGS_NOT_EQUAL);
    PRINT_INST_NAME(SET);
    PRINT_INST_NAME(ADD);
    PRINT_INST_NAME(LOAD_CHAR);
    PRINT_INST_NAME(LOAD_REG_INTO_REG);
    PRINT_INST_NAME(REG_BITWISE_OR);
    PRINT_INST_NAME(REG_BITWISE_AND);
    PRINT_INST_NAME(REG_BITWISE_XOR);
    PRINT_INST_NAME(REG_ADD);
    PRINT_INST_NAME(REG_SUB);
    PRINT_INST_NAME(REG_SUB_N);
    PRINT_INST_NAME(REG_SHIFT_R);
    PRINT_INST_NAME(REG_SHIFT_L);
    PRINT_INST_NAME(SET_IDX);
    PRINT_INST_NAME(RND);
    PRINT_INST_NAME(DISPLAY);
    PRINT_INST_NAME(SKIP_KEY_DOWN);
    PRINT_INST_NAME(SKIP_KEY_UP);
    PRINT_INST_NAME(LOAD_DELAY_TIMER);
    PRINT_INST_NAME(LOAD_KEY_PRESS);
    PRINT_INST_NAME(SET_DELAY_TIMER);
    PRINT_INST_NAME(SET_SOUND_TIMER);
    PRINT_INST_NAME(ADD_INDEX);
    PRINT_INST_NAME(LOAD_BCD);
    PRINT_INST_NAME(STORE_REGS);
    PRINT_INST_NAME(LOAD_REGS);
  }

  switch (inst.tag) {
  // addr
  case JUMP:
  case CALL:
  case SET_IDX:
  case JUMP_OFFSET: printf(" (addr)    addr=0x%04x", inst.data.addr); break;
  // reg value
  case SKIP_IF_EQUAL:
  case SKIP_IF_NOT_EQUAL:
  case SET:
  case ADD:
  case RND:
    printf(" (reg_val) vx=v%x, val=%d", inst.data.reg_val.reg,
           inst.data.reg_val.val);
    break;
  // reg reg
  case SKIP_IF_REGS_EQUAL:
  case LOAD_REG_INTO_REG:
  case REG_BITWISE_OR:
  case REG_BITWISE_AND:
  case REG_BITWISE_XOR:
  case REG_ADD:
  case REG_SUB:
  case REG_SHIFT_R:
  case REG_SHIFT_L:
  case REG_SUB_N:
  case SKIP_IF_REGS_NOT_EQUAL:
    printf(" (reg_reg) vx=v%x, vy=v%x", inst.data.reg_reg.vx,
           inst.data.reg_reg.vy);
    break;
  // reg
  case SKIP_KEY_DOWN:
  case SKIP_KEY_UP:
  case LOAD_CHAR:
  case LOAD_DELAY_TIMER:
  case LOAD_KEY_PRESS:
  case SET_DELAY_TIMER:
  case SET_SOUND_TIMER:
  case ADD_INDEX:
  case LOAD_BCD:
  case STORE_REGS:
  case LOAD_REGS: printf(" (reg)     vx=v%x", inst.data.reg); break;
  // XYH_INST
  case DISPLAY:
    printf(" (display) vx=v%x, vy=v%x height=%d", inst.data.display.vx,
           inst.data.display.vy, inst.data.display.height);
    break;
  default: printf(" (void)"); break;
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
