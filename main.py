import levrt
from lev.shadow1ng.fscan import fscan

async def main():
    doc = await  fscan.main(host="8.8.8.8", argv="-p 80")
    data = await doc.get()
    print(data)


if __name__ == "__main__":
    levrt.run(main())
