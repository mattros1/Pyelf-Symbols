from os import name
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class ELFAnalyzer:

  def __init__(self, path):
    self.path = path

  def symbols(self):
    sym_info = {}
    with open(self.path, 'rb') as file:
      elf = ELFFile(file)
      for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
          continue
        for symbol in section.iter_symbols():
          if (symbol['st_size'] == 0):
            continue
          sym_info[symbol.name] = {
              'address': symbol['st_value'],
              'size': symbol['st_size'],
              'padding': 0
          }

      #sort by address to ensure contiguous symbols
      sorted_names = sorted(sym_info.keys(),
                            key=lambda name: sym_info[name]['address'],
                            reverse=False)

      #assign padding based on difference in address
      for i, name in enumerate(sorted_names):
        if (i == 0):
          continue
        prev_sym = sym_info[sorted_names[i - 1]]
        cur_sym = sym_info[name]
        prev_sym['padding'] = cur_sym['address'] - prev_sym[
            'address'] - prev_sym['size']

      #sort by size
      sorted_names = sorted(sym_info.keys(),
                            key=lambda name: sym_info[name]['size'],
                            reverse=True)

      #print symbols in order of size with padding
      for name in sorted_names:
        cur_sym = sym_info[name]
        print(
            f"Name: {name}, Address: {hex(cur_sym['address'])}, Size: {hex(cur_sym['size'])}, Padding: {hex(cur_sym['padding'])}"
        )


if __name__ == '__main__':
  elf = "test"
  analyzer = ELFAnalyzer(elf)
  analyzer.symbols()
