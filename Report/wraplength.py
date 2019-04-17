#!/usr/bin/python3
words = input().split()

print("="*50)

linlen = 0
for word in words:
    if linlen + len(word) > 100:
        print(f"\n{word}",end=" ")
        linlen = len(word) + 1
    else:
        print(f"{word}",end=" ")
        linlen += len(word) + 1
print()
