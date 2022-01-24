# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sel-melc <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/10/15 19:41:09 by sel-melc          #+#    #+#              #
#    Updated: 2019/11/18 15:58:03 by sel-melc         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #


SRC = famine.asm

CC = ld
OBJ = $(SRC:.asm=.o) 

SRC_BONUS = famine_bonus.asm

OBJ_BONUS = $(SRC_BONUS:.asm=.o)

NAME = Famine

all : $(NAME)

$(NAME) : $(OBJ)
	$(CC) -o $(NAME) $(OBJ)
	cp sc /tmp/

bonus: $(OBJ_BONUS)
	$(CC) -o $(NAME) $(OBJ_BONUS)
	cp cc /tmp/

$(OBJ): $(SRC)
	nasm -felf64 $(SRC)

$(OBJ_BONUS): $(SRC_BONUS)
	nasm -felf64 $(SRC_BONUS)
#%.o: %.s
#	nasm -felf64 $(SRC)

clean : 
	rm -f $(OBJ) $(OBJ_BONUS)  a.out /tmp/test/* /tmp/test2/*
fclean : clean
	rm -f $(NAME)

re : fclean all

.PHONY : clean fclean re all
