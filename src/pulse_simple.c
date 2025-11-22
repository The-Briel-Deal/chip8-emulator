/***
  This file is part of PulseAudio.

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <pulse/sample.h>
#include <stdint.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <pulse/error.h>
#include <pulse/simple.h>

#define M_PI_M2 (M_PI + M_PI)

#define C_4_PITCH 261.63

#define DEFAULT_RATE 44100
#define DEFAULT_CHANNELS 2
#define DEFAULT_VOLUME 0.7

#define BUFSIZE DEFAULT_RATE * 4

int main() {

  /* The Sample format to use */
  static const pa_sample_spec ss = {.format = PA_SAMPLE_S16LE,
                                    .rate = DEFAULT_RATE,
                                    .channels = DEFAULT_CHANNELS};

  pa_simple *s = NULL;
  int ret = 1;
  int error;
  double accum = 0;

  /* Create a new playback stream */
  if (!(s = pa_simple_new(NULL, "test stream", PA_STREAM_PLAYBACK, NULL,
                          "playback", &ss, NULL, NULL, &error))) {
    fprintf(stderr, __FILE__ ": pa_simple_new() failed: %s\n",
            pa_strerror(error));
    goto finish;
  }

  int frame_size = pa_frame_size(&ss);

  assert(frame_size == 4);

  for (int write_count = 0; write_count < 2; write_count++) {
    uint8_t buf[BUFSIZE];
    ssize_t r;

#if 0
        pa_usec_t latency;
 
        if ((latency = pa_simple_get_latency(s, &error)) == (pa_usec_t) -1) {
            fprintf(stderr, __FILE__": pa_simple_get_latency() failed: %s\n", pa_strerror(error));
            goto finish;
        }
 
        fprintf(stderr, "%0.0f usec    \r", (float)latency);
#endif

    for (int i = 0; i < sizeof(buf);) {
      accum += M_PI_M2 * C_4_PITCH / DEFAULT_RATE;
      printf("data->accumulator=%lf\n", accum);
      if (accum >= M_PI_M2) accum -= M_PI_M2;
      int16_t val = sin(accum) * DEFAULT_VOLUME * 32767.0;
      *(uint16_t *)(&buf[i]) = val;
      *(uint16_t *)(&buf[i + 2]) = val;

      i += frame_size;
    }

    /* ... and play it */
    if (pa_simple_write(s, buf, sizeof(buf), &error) < 0) {
      fprintf(stderr, __FILE__ ": pa_simple_write() failed: %s\n",
              pa_strerror(error));
      goto finish;
    }
  }

  /* Make sure that every single sample was played */
  if (pa_simple_drain(s, &error) < 0) {
    fprintf(stderr, __FILE__ ": pa_simple_drain() failed: %s\n",
            pa_strerror(error));
    goto finish;
  }

  ret = 0;

finish:

  if (s) pa_simple_free(s);

  return ret;
}
