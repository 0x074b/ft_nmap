NAME		:= ft_nmap
PARSING		:= parsing

CC			:= gcc
CFLAGS		:= -Wall -Wextra -Werror -g
INCLUDES	:= -I includes
LDLIBS		:= -lpcap -lpthread

SRC_DIR		:= src
OBJ_DIR		:= obj

SRCS		:= \
	src/main.c \
	src/network/interface.c \
	src/packet/ip_header.c \
	src/parser/parse_opts.c \
	src/parser/utils.c \
	src/pcap/pcap_init.c \
	src/report/report.c \
	src/scanner/scan.c \
	src/scanner/syn_scan.c \
	src/scanner/ack_scan.c \
	src/scanner/fin_scan.c \
	src/scanner/null_scan.c \
	src/scanner/xmas_scan.c \
	src/scanner/udp_scan.c \
	src/thread/thread_pool.c \
	src/detection/os_detect.c \
	src/detection/service_detect.c

SRCS_PARSING	:= \
	src/parser/test.c \
	src/parser/parse_opts.c \
	src/parser/utils.c

OBJS			:= $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJS_PARSING	:= $(SRCS_PARSING:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS			:= $(OBJS:.o=.d) $(OBJS_PARSING:.o=.d)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDLIBS)

$(PARSING): $(OBJS_PARSING)
	$(CC) $(CFLAGS) $(OBJS_PARSING) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -MMD -MP -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME) $(PARSING)

re: fclean all

-include $(DEPS)

.PHONY: all clean fclean re
