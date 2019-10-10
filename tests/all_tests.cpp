//
// Created by eugene on 6/27/19.
//

#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include <catch2/catch.hpp>
#include "../inc_internal/utils.h"
#include <nf/errors.h>

int init() {
    init_debug();
    return 0;
}

static int _init = init();
