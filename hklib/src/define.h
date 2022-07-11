#pragma once

#ifdef MAKEDLL
#define EXPORT __declspec(dllexport)
#define C_EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#define C_EXPORT extern "C" __declspec(dllimport)
#endif