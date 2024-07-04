import argparse
import hashlib
import hmac

def hdigest(key, data, alg=hashlib.sha512):

  h = hmac.new(key.encode("ascii"), data.encode("ascii"), alg)
  return h.hexdigest().upper()

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("key", type=str)
  parser.add_argument("data", type=str)
  parser.add_argument("algorithm", choices=["md5", "sha512"])

  args = parser.parse_args()

  digest = hdigest(args.key, args.data, getattr(hashlib, args.algorithm))
  print("HMAC digest:", digest)

if __name__ == "__main__":
  main()