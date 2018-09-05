#!/bin/bash
sudo pkill -9 sr_solution
sudo pkill -9 sr
sudo pkill -9 sr_nat
sudo mn -c
sudo pkill -9 python
