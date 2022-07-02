#!/usr/bin/env python
"""

Copyright (c) 2022 Alex Forencich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""

import itertools
import logging
import os
import random
import sys

import cocotb_test.simulator
import pytest

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
from cocotb.regression import TestFactory

from cocotbext.pcie.core.tlp import Tlp, TlpType


try:
    from pcie_if import PcieIfSource, PcieIfSink, PcieIfBus, PcieIfFrame
except ImportError:
    # attempt import from current directory
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    try:
        from pcie_if import PcieIfSource, PcieIfSink, PcieIfBus, PcieIfFrame
    finally:
        del sys.path[0]


class TB(object):
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger("cocotb.tb")
        self.log.setLevel(logging.DEBUG)

        cocotb.start_soon(Clock(dut.clk, 4, units="ns").start())

        self.source = PcieIfSource(PcieIfBus.from_prefix(dut, "in_tlp"), dut.clk, dut.rst)
        self.sink = PcieIfSink(PcieIfBus.from_prefix(dut, "out_tlp"), dut.clk, dut.rst)

    def set_idle_generator(self, generator=None):
        if generator:
            self.source.set_pause_generator(generator())

    def set_backpressure_generator(self, generator=None):
        if generator:
            self.sink.set_pause_generator(generator())

    async def cycle_reset(self):
        self.dut.rst.setimmediatevalue(0)
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)
        self.dut.rst.value = 1
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)
        self.dut.rst.value = 0
        await RisingEdge(self.dut.clk)
        await RisingEdge(self.dut.clk)


async def run_test(dut, payload_lengths=None, payload_data=None, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    seg_count = len(tb.source.bus.valid)
    seq_count = 2**(len(tb.source.bus.seq) // seg_count)

    cur_seq = 1

    await tb.cycle_reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    test_tlps = []
    test_frames = []

    for test_data in [payload_data(x) for x in payload_lengths()]:
        test_tlp = Tlp()

        if len(test_data):
            test_tlp.fmt_type = TlpType.MEM_WRITE
            test_tlp.set_addr_be_data(cur_seq*4, test_data)
        else:
            test_tlp.fmt_type = TlpType.MEM_READ
            test_tlp.set_addr_be(cur_seq*4, 4)

        test_frame = PcieIfFrame.from_tlp(test_tlp)
        test_frame.seq = cur_seq

        test_tlps.append(test_tlp)
        test_frames.append(test_frame)
        await tb.source.send(test_frame)

        cur_seq = (cur_seq + 1) % seq_count

    for test_tlp in test_tlps:
        rx_frame = await tb.sink.recv()

        rx_tlp = rx_frame.to_tlp()

        assert rx_tlp == test_tlp

    assert tb.sink.empty()

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


async def run_test_init_sink_pause(dut):

    tb = TB(dut)

    await tb.cycle_reset()

    tb.sink.pause = True

    test_data = bytearray(itertools.islice(itertools.cycle(range(256)), 128))
    test_tlp = Tlp()

    test_tlp.fmt_type = TlpType.MEM_WRITE
    test_tlp.set_addr_be_data(0, test_data)

    test_frame = PcieIfFrame.from_tlp(test_tlp)

    await tb.source.send(test_frame)

    for k in range(64):
        await RisingEdge(dut.clk)

    tb.sink.pause = False

    rx_frame = await tb.sink.recv()

    rx_tlp = rx_frame.to_tlp()

    assert rx_tlp == test_tlp

    assert tb.sink.empty()

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


async def run_test_init_sink_pause_reset(dut):

    tb = TB(dut)

    await tb.cycle_reset()

    tb.sink.pause = True

    test_data = bytearray(itertools.islice(itertools.cycle(range(256)), 128))
    test_tlp = Tlp()

    test_tlp.fmt_type = TlpType.MEM_WRITE
    test_tlp.set_addr_be_data(0, test_data)

    test_frame = PcieIfFrame.from_tlp(test_tlp)

    await tb.source.send(test_frame)

    for k in range(64):
        await RisingEdge(dut.clk)

    await tb.cycle_reset()

    tb.sink.pause = False

    for k in range(64):
        await RisingEdge(dut.clk)

    assert tb.sink.empty()

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


async def run_stress_test(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    seg_count = len(tb.source.bus.valid)
    seq_count = 2**(len(tb.source.bus.seq) // seg_count)

    cur_seq = 1

    await tb.cycle_reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    test_tlps = []

    for k in range(128):
        length = random.randint(1, 512)
        test_tlp = Tlp()
        test_tlp.fmt_type = random.choice([TlpType.MEM_WRITE, TlpType.MEM_READ])
        if test_tlp.fmt_type == TlpType.MEM_WRITE:
            test_data = bytearray(itertools.islice(itertools.cycle(range(256)), length))
            test_tlp.set_addr_be_data(cur_seq*4, test_data)
        elif test_tlp.fmt_type == TlpType.MEM_READ:
            test_tlp.set_addr_be(cur_seq*4, length)
            test_tlp.tag = cur_seq

        test_frame = PcieIfFrame.from_tlp(test_tlp)
        test_frame.seq = cur_seq

        test_tlps.append(test_tlp)
        await tb.source.send(test_frame)

        cur_seq = (cur_seq + 1) % seq_count

    for test_tlp in test_tlps:
        rx_frame = await tb.sink.recv()

        rx_tlp = rx_frame.to_tlp()

        assert rx_tlp == test_tlp

    assert tb.sink.empty()

    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


def size_list():
    return list(range(0, 512+1, 4))+[4]*64


def incrementing_payload(length):
    return bytearray(itertools.islice(itertools.cycle(range(256)), length))


if cocotb.SIM_NAME:

    factory = TestFactory(run_test)
    factory.add_option("payload_lengths", [size_list])
    factory.add_option("payload_data", [incrementing_payload])
    factory.add_option("idle_inserter", [None, cycle_pause])
    factory.add_option("backpressure_inserter", [None, cycle_pause])
    factory.generate_tests()

    for test in [
                run_test_init_sink_pause,
                run_test_init_sink_pause_reset
            ]:

        factory = TestFactory(test)
        factory.generate_tests()

    factory = TestFactory(run_stress_test)
    factory.add_option("idle_inserter", [None, cycle_pause])
    factory.add_option("backpressure_inserter", [None, cycle_pause])
    factory.generate_tests()


# cocotb-test

tests_dir = os.path.dirname(__file__)
rtl_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', 'rtl'))


@pytest.mark.parametrize(("pcie_data_width", "in_tlp_seg_count", "out_tlp_seg_count"),
    [(64, 1, 1), (128, 1, 1), (256, 1, 1), (256, 1, 2), (256, 2, 1), (512, 1, 1), (512, 1, 2),
    (512, 1, 4), (512, 2, 1), (512, 4, 1), (512, 2, 2), (512, 2, 4), (512, 4, 2), (512, 4, 4)])
def test_pcie_tlp_fifo(request, pcie_data_width, in_tlp_seg_count, out_tlp_seg_count):
    dut = "pcie_tlp_fifo"
    module = os.path.splitext(os.path.basename(__file__))[0]
    toplevel = dut

    verilog_sources = [
        os.path.join(rtl_dir, f"{dut}.v"),
        os.path.join(rtl_dir, "pcie_tlp_fifo_raw.v"),
    ]

    parameters = {}

    parameters['DEPTH'] = 4096
    parameters['TLP_DATA_WIDTH'] = pcie_data_width
    parameters['TLP_STRB_WIDTH'] = parameters['TLP_DATA_WIDTH'] // 32
    parameters['TLP_HDR_WIDTH'] = 128
    parameters['IN_TLP_SEG_COUNT'] = in_tlp_seg_count
    parameters['OUT_TLP_SEG_COUNT'] = out_tlp_seg_count

    extra_env = {f'PARAM_{k}': str(v) for k, v in parameters.items()}

    sim_build = os.path.join(tests_dir, "sim_build",
        request.node.name.replace('[', '-').replace(']', ''))

    cocotb_test.simulator.run(
        python_search=[tests_dir],
        verilog_sources=verilog_sources,
        toplevel=toplevel,
        module=module,
        parameters=parameters,
        sim_build=sim_build,
        extra_env=extra_env,
    )
