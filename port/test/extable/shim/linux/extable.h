#pragma once
void sort_extable(struct exception_table_entry *start,
		  struct exception_table_entry *finish);
const struct exception_table_entry *
search_extable(const struct exception_table_entry *base,
	       const size_t num, unsigned long value);
