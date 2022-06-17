from posixpath import split
import levrt
from levrt import Cr, ctx, remote, annot,File
from levrt.annot.cats import Attck, BlackArch

@annot.meta(
    desc="fscan 扫描hosts",
    params=[
    annot.Param("host", "扫描目标",holder="8.8.8.8"),
    ],
    
    cats=[Attck.Reconnaissance],
)
def main(host: str = "") -> Cr:
    """
    fscan扫描器
    ```
    await fscan("8.8.8.8")
    ```
    """
    @levrt.remote
    def entry():
        import logging
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        import subprocess
        output = subprocess.check_output(['/fscan','-h',host], text=True,stderr=subprocess.STDOUT)
        logger.debug(output)
        ctx.set(msg=output)
        # result =  {"result": output}
        # ctx.update(result)

    return Cr("de4f1a823caa", entry=entry())

@annot.meta(
    desc="fscan 扫描hosts 带参数",
    params=[
    annot.Param("host", "扫描目标",holder="8.8.8.8"),
    annot.Param("argv", "其他扫描参数",holder="-np"),
    ],
    
    cats=[Attck.Reconnaissance],
)
def main1(host: str = "",argv:str="",) -> Cr:
    """
    fscan扫描器
    ```
    await fscan("8.8.8.8")
    ```
    """
    @levrt.remote
    def entry():
        import logging
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        import subprocess
        if argv != "":
            argvs = argv.split(" ")
            output = subprocess.check_output(['/fscan','-h',host,*argvs], text=True,stderr=subprocess.STDOUT)
        else:
            output = subprocess.check_output(['/fscan','-h',host], text=True,stderr=subprocess.STDOUT)
        logger.debug(output)
        ctx.set(msg=output)
        # result =  {"result": output}
        # ctx.update(result)

    return Cr("de4f1a823caa", entry=entry())

@annot.meta(
    desc="fscan 扫描urls",
    params=[
    annot.Param("url", "扫描目标",holder="www.baidu.com"),
    ],
    
    cats=[Attck.Reconnaissance],
)
def url(url: str = "") -> Cr:
    """
    fscan扫描器
    ```
    await fscan("8.8.8.8")
    ```
    """
    @levrt.remote
    def entry():
        import logging
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        import subprocess
        output = subprocess.check_output(['/fscan','-u',url], text=True,stderr=subprocess.STDOUT)
        logger.debug(output)
        ctx.set(msg=output)
        # result =  {"result": output}
        # ctx.update(result)

    return Cr("de4f1a823caa", entry=entry())

@annot.meta(
    desc="fscan 扫描urls 带参数",
    params=[
    annot.Param("url", "扫描目标",holder="www.baidu.com"),
    annot.Param("argv", "其他扫描参数",holder="-nopoc"),
    ],
    
    cats=[Attck.Reconnaissance],
)
def url1(url: str = "",argv:str="",) -> Cr:
    """
    fscan扫描器
    ```
    await fscan("8.8.8.8")
    ```
    """
    @levrt.remote
    def entry():
        import logging
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        import subprocess
        if argv != "":
            argvs = argv.split(" ")
            output = subprocess.check_output(['/fscan','-u',url,*argvs], text=True,stderr=subprocess.STDOUT)
        else:
            output = subprocess.check_output(['/fscan','-u',url], text=True,stderr=subprocess.STDOUT)
        logger.debug(output)
        ctx.set(msg=output)
        # result =  {"result": output}
        # ctx.update(result)

    return Cr("de4f1a823caa", entry=entry())
# @annot.meta(
#     desc="扫描hosts文件",
#     params=[
#     annot.Param("hostfile", "hosts文件"),
#     annot.Param("argv", "其他扫描参数"),
#     ],
    
#     cats=[Attck.Reconnaissance],
# )
# def hostfile(hostfile: File=None,argv:str="",) -> Cr:
#     """
#     fscan扫描器
#     ```
#     await fscan("8.8.8.8")
#     ```
#     """
#     @levrt.remote
#     def entry():
#         import logging
#         logging.basicConfig()
#         logger = logging.getLogger("lev")
#         logger.setLevel(logging.DEBUG)
#         import subprocess
#         output = subprocess.check_output(['cat','/hosts.txt'], text=True,stderr=subprocess.STDOUT)
#         logger.debug(output)
#         ctx.set(msg=output)


#     return Cr("de4f1a823caa", entry=entry(), files={"/hosts.txt": hostfile})


__lev__ = annot.meta([main,main1,url,url1],
                     desc = "fscan", # name of tool
                     cats = {
                        Attck: [Attck.Reconnaissance] # ATT&CK
                     })