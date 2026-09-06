#pragma once
#define EXPORT_SYMBOL_GPL(sym)
#define EXPORT_SYMBOL(sym)
#define __alias(symbol) __attribute__((alias(#symbol)))
