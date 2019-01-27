COMMAND="PYTHONPATH=\"$PWD/modules:"'$PYTHONPATH"'
[ -f ~/.bashrc ] && echo "$COMMAND" >> ~/.bashrc
[ -f ~/.zshrc ] && echo "$COMMAND" >> ~/.zshrc

