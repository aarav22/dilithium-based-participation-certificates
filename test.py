import hashlib

tbs_data ={
  "Xmp.pdf.Author": "aarav_secondary",
  "Xmp.xmp.CreatorTool": "Canva",
  "Xmp.dc.title": "lang=\"x-default\" Red White Professional Certificate Of Appreciation - 1",
  "Xmp.dc.creator": [
    "Dilithium2"
  ],
  "Xmp.Attrib.Ads": "type=\"Seq\"",
  "Xmp.Attrib.Ads[1]": "type=\"Struct\"",
  "Xmp.Attrib.Ads[1]/Attrib:Created": "2023-07-31",
  "Xmp.Attrib.Ads[1]/Attrib:ExtId": "6f747215-1475-496c-8a98-d99e4d3ad6ae",
  "Xmp.Attrib.Ads[1]/Attrib:FbId": "525265914179580",
  "Xmp.Attrib.Ads[1]/Attrib:TouchType": "2"
}

tbs_data_hash = hashlib.sha256(str(tbs_data).encode('utf-8')).digest()

print(tbs_data_hash.hex())