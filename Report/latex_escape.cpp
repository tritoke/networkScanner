#include <iostream>

int main(void) {
  std::string s;
  std::getline (std::cin, s);
  for (unsigned int i = 0; i < s.length(); i++) {
    if (s[i] == '&') {
      printf("\\&");
    } else if (s[i] == '%') {
      printf("\\%%");
    } else if (s[i] == '$') {
      printf("\\$");
    } else if (s[i] == '#') {
      printf("\\#");
    } else if (s[i] == '_') {
      printf("\\_");
    } else if (s[i] == '{') {
      printf("\\{");
    } else if (s[i] == '}') {
      printf("\\}");
    } else if (s[i] == '~') {
      printf("{\\textasciitilde}");
    } else if (s[i] == '^') {
      printf("{\\textasciicircum}");
    } else if (s[i] == '\\') {
      printf("{\\textbackslash}");
    } else {
      printf("%c", s[i]);
    }
  }

  printf("\n");

  return 0;
}
