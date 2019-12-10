# Copyright (C) 2019 Amazon.com, Inc. or its affiliates.
# Author: Pawel Wieczorkiewicz <wipawel@amazon.de>
#
# This plugin opens a window with a generated list of non-init
# sections' functions referencing all symbols from .init sections.
# As well as their callers or data references.
#
# Example output:
#.rodata    0xffff82d080401600 amd_cpu_dev
#    .text      0xffff82d0802e6a83 init_amd
#            call    check_enable_amd_mmconf_dmi                .init.text 0xffff82d08043f5d5
#
# Addresses and symbol names are double-clickable, allowing to
# jump to corresponding dissasembly.

import idaapi
import idautils
import idc
from itertools import chain

PLUGIN_NAME = "Check .init references"
PLUGIN_COMMENT = "Check .init sections references by non-init functions"
WINDOW_NAME = ".init references"


class Initrefview_t(idaapi.simplecustviewer_t):
    def Create(self, name):
        return True if idaapi.simplecustviewer_t.Create(self, name) else False

    def OnDblClick(self, shift):
        word = self.GetCurrentWord()
        if not word:
            return True

        addr = None
        try:
            addr = int(word, 16)
        except:
            sym = word.split(':')[1] if ':' in word else word
            addr = idaapi.get_name_ea(idaapi.BADADDR, sym)

        if addr:
            idaapi.jumpto(addr)
        return True


class Checkinitplg(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Alt-F8"

    def __init__(self):
        self.view = None

    def init(self):
        self.init_segm = set()
        self.non_init_segm = set()
        self.refs = dict()

        return idaapi.PLUGIN_KEEP

    @staticmethod
    def is_seg_init(ea):
        return idaapi.get_segm_name(idaapi.getseg(ea)).startswith('.init')

    @staticmethod
    def is_ea_in_segs(ea, segs):
        for start, end in segs:
            if start <= ea <= end:
                return True
        return False

    @staticmethod
    def get_segm_name(ea, align=10):
        seg = idaapi.get_segm_name(idaapi.getseg(ea))
        line = idaapi.add_spaces(seg, align)
        return idaapi.COLSTR(line, idaapi.SCOLOR_SEGNAME)

    @staticmethod
    def get_addr(ea):
        return idaapi.COLSTR('%#x' % ea, idaapi.SCOLOR_NUMBER)

    @staticmethod
    def get_func_name(ea):
        name = idaapi.get_func_name(ea)
        if not name:
            name = idaapi.get_ea_name(ea)
        return idaapi.COLSTR(name, idaapi.SCOLOR_SYMBOL)

    @staticmethod
    def get_disasm(ea, align=50):
        # GetDisasm() sometimes returns a few bytes from next instruction:
        # https://www.hex-rays.com/products/ida/support/idapython_docs/idc-module.html#GetDisasm
        asm = idc.GetDisasm(ea).split(';')[0]

        # Format the line to always be at least 'align' number of chars
        line = idaapi.add_spaces(asm, align)
        return idaapi.COLSTR(line, idaapi.SCOLOR_INSN)

    def display_refs(self):
        for func in self.refs.keys():
            self.view.AddLine("")

            to_refs = self.refs[func]['to']
            for ea in to_refs:
                self.view.AddLine("%s %s %s" % (
                    self.get_segm_name(ea),
                    self.get_addr(ea),
                    self.get_func_name(ea))
                )

            self.view.AddLine("\t%s %s %s" % (
                self.get_segm_name(func),
                self.get_addr(func),
                self.get_func_name(func))
            )

            from_refs = self.refs[func]['from']
            for insn, target in from_refs:
                self.view.AddLine("\t\t%s %s %s %s" % (
                    self.get_addr(insn),
                    self.get_disasm(insn),
                    self.get_segm_name(target),
                    self.get_addr(target))
                )

    def generate_refs(self):
        for start, end in self.non_init_segm:
            for func in idautils.Functions(start, end):
                for item in idautils.FuncItems(func):
                    for xref in chain(idautils.DataRefsFrom(item), idautils.CodeRefsFrom(item, 1)):
                        if self.is_ea_in_segs(xref, self.init_segm):
                            if not self.refs.get(func, None):
                                self.refs[func] = { 'to': set(), 'from': set() }
                            self.refs[func]['from'].add((item, xref))
                            for to_xref in chain(idautils.DataRefsTo(func), idautils.CodeRefsTo(func, 1)):
                                self.refs[func]['to'].add(to_xref)

    def run(self, arg):
        self.term()

        self.view = Initrefview_t()
        if not self.view.Create(WINDOW_NAME):
            return

        for start in idautils.Segments():
            segm = self.init_segm if self.is_seg_init(start) else self.non_init_segm
            segm.add((start, idaapi.getseg(start).end_ea))

        if not self.refs:
            self.generate_refs()

        self.display_refs()
        self.view.Show()

    def term(self):
        if self.view:
            self.view.Close()


def PLUGIN_ENTRY():
    return Checkinitplg()
