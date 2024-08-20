import os
import lzo
import wut

def test_lzo_with_metadata():
    corpus = {}
    for algo in ['LZO1', 'LZO1A', 'LZO1B', 'LZO1C', 'LZO1F', 'LZO1X', 'LZO1Y', 'LZO1Z', 'LZO2A']:
        for diff in range(1,10):
            x = lzo.compress(os.urandom(100),diff,True,algorithm=algo)
            corpus[f'{algo}_{diff}'] = x

    for name,val in corpus.items():
        print(name)
        assert wut.is_lzo(val) is True

def test_lzo_without_metadata():
    corpus = {}
    for algo in ['LZO1', 'LZO1A', 'LZO1B', 'LZO1C', 'LZO1F', 'LZO1X', 'LZO1Y', 'LZO1Z', 'LZO2A']:
        for diff in range(1,10):
            x = lzo.compress(os.urandom(100),diff,False,algorithm=algo)
            corpus[f'{algo}_{diff}_no_header'] = x

    for name,val in corpus.items():
        print(name)
        assert wut.is_lzo(val) is True