#include "parsing.h"
int		parse_opts(int argc, char **argv, t_options *opts);

int main(int argc, char **argv)
{
	t_options	opts;
	parse_opts(argc, argv, &opts);
}