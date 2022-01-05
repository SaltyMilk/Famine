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


SRC = famine.s

CC = ld
OBJ = $(SRC:.s=.o) 

NAME = Famine

all : $(NAME)

$(NAME) : $(OBJ)
	$(CC) -o $(NAME) $(OBJ)


%.o: %.s
	nasm -felf64 $(SRC)

clean : 
	rm -f $(OBJ)
fclean :
	rm -f $(OBJ) $(NAME)

re : fclean all

.PHONY : clean fclean re all
