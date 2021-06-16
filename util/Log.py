import logging

logging.basicConfig(level=logging.DEBUG,
                    filename="log/BTCapture.log"
                    , filemode='a'
                    , format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'
                    )

def getlogger() -> logging:
    return logging
