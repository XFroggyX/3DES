import sys
import argparse
from encode import generate_key, generate_iv, encode
from decode import decode
import time

if __name__ == '__main__':
    t0 = time.time()
    parser = argparse.ArgumentParser(description='Encode/decode file')
    parser.add_argument('--Genkey', dest="type_operation", type=str)
    parser.add_argument('--Genvec', dest="type_operation", type=str)
    parser.add_argument('--Code', dest="type_operation", type=str)
    parser.add_argument('--Decode', dest="type_operation", type=str)
    parser.add_argument('--File', dest='save_file', default='text.txt', type=str)
    parser.add_argument('--Key', dest='key', type=str)
    parser.add_argument('--Vec', dest='vec', type=str)
    parser.add_argument('--Mod', dest='mod', type=str)

    args = parser.parse_args()

    if sys.argv.count("--Code"):
        encode(args.type_operation, args.key, args.save_file, args.vec, args.mod)
    elif sys.argv.count("--Decode"):
        decode(args.type_operation, args.key, args.vec, args.mod, args.save_file)
    elif sys.argv.count("--Genkey"):
        print(generate_key(args.type_operation))
    elif sys.argv.count("--Genvec"):
        print(generate_iv(args.type_operation))
    else:
        print(argparse.ArgumentTypeError("Operation type not specified"))
    t1 = time.time() - t0
    print("--- %s seconds ---" % t1)

"""--Code text.txt --Key key.bin --File encode_text.txt --Vec vec.bin --Mod ECB"""
"""--Decode encode_text.txt --Key key.bin --File dectext.txt --Vec vec.bin --Mod ECB"""
