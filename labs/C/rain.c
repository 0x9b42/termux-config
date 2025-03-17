#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CHARS                                                                  \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()"
#define SLEEP_TIME 50000
#define DROP_PROBABILITY 50

void get_terminal_size(int *rows, int *cols) {
  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  *rows = w.ws_row;
  *cols = w.ws_col;
}

void matrix_rain() {
  int rows, cols;
  get_terminal_size(&rows, &cols);
  int *columns = calloc(cols, sizeof(int));
  srand(time(NULL));

  while (1) {
    printf("\033[H"); // Move cursor to home to avoid flicker

    for (int i = 0; i < cols; i++) {
      if ((rand() % DROP_PROBABILITY) < 1) {
        columns[i] = 0;
      }
      if (columns[i] < rows) {
        columns[i]++;
      }
    }

    for (int y = 0; y < rows; y++) {
      for (int x = 0; x < cols; x++) {
        putchar(columns[x] > y ? CHARS[rand() % (sizeof(CHARS) - 1)] : ' ');
      }
      putchar('\n');
    }

    usleep(SLEEP_TIME);
  }

  free(columns);
}

int main() {
  struct termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ECHO | ICANON);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  matrix_rain();

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  return 0;
}
