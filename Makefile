NAME		:= ft_ping

OBJ_DIR		:= build

SRC_FILES	:= ping.c
OBJ_FILES	:= $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES))
DEP_FILES	:= $(patsubst %.c,$(OBJ_DIR)/%.d,$(SRC_FILES))

CFLAGS		:= -Wall -Wextra -MMD -MP
LFLAGS		:=

LINK_CMD	:= $(CC)

all: $(NAME)

$(NAME): $(OBJ_FILES)
	$(LINK_CMD) $(LFLAGS) -o $@ $(OBJ_FILES)

$(OBJ_DIR)/%.o: %.c Makefile
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean:
	${MAKE} clean
	rm -f $(NAME)

re:
	${MAKE} fclean
	${MAKE}

fmt:
	clang-format -i $(SRC_FILES)

.PHONY: all clean fclean re check format
-include $(DEP_FILES)
