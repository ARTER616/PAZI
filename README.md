# PAZI
Лабораторная работа по ПАЗИ

Для работы программы необходима библиотека OpenSSL.

# Сборка проекта на Windows
1. Склонировать репозиторий и перейти в папку с проектом
2. mkdir build
3. cd build
4. cmake -G “MinGW Makefiles” -DOPENSSL_ROOT_DIR=”C:\OpenSSL” ..
5. mingw32-make.exe

# Сборка проекта на *nix
1. Склонировать репозиторий и перейти в папку с проектом
2. mkdir build
3. cd build
4. cmake ..
5. make
