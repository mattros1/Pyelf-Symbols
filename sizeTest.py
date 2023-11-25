from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class ELFAnalyzer:

  def __init__(self, path):
    self.path = path
    self.sInfo = {}

  def symbols(self):
    with open(self.path, 'rb') as file:
      elf = ELFFile(file)
      #iterate through each section
      for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
          continue
        #iterate through each symbol
        for cnt, symbol in enumerate(section.iter_symbols()):
          name = symbol.name
          addr = symbol['st_value']
          size = symbol['st_size']

          self.sInfo[name] = {'address': addr, 'size': size, 'padding': 0}
          prev = symbol
      #sort by adress to ensure contiguous symbols
      sortedSymbols = sorted(self.sInfo.items(),
                             key=lambda x: x[1]['address'],
                             reverse=False)
      prev = None
      prevName = None
      #assign padding based on difference in addresses
      for sName, info in sortedSymbols:
        if (prev != None):
          self.sInfo[prevName][
              'padding'] = info['address'] - prev['address'] - prev['size']
        prev = info
        prevName = sName

      #sort by size
      sortedSymbols = sorted(sortedSymbols,
                             key=lambda x: x[1]['size'],
                             reverse=True)
      #print symbols in order of size with padding
      for sName, info in sortedSymbols:
        print(
            f"Name: {sName}, Address: {hex(info['address'])}, Size: {hex(info['size'])}, Padding: {hex(info['padding'])}"
        )


if __name__ == '__main__':
  elf = "test"
  analyzer = ELFAnalyzer(elf)
  analyzer.symbols()
