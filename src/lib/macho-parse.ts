import * as forge from "node-forge";
import * as zip from "@zip.js/zip.js"; // efficient framework for unzipping | lists entries first instead of extracting all |
import * as bplist from "./bplist-parse";

class Uint32 {
  private _value: number;

  get value(): number {
    return this._value;
  }

  set value(newValue: number) {
    if (newValue !== (newValue & 0xff)) return;
    this._value = newValue;
  }
}

type cpu_type_t = Uint32; // integer is also 4 bytes sooooo
type cpu_subtype_t = Uint32;
interface mach_header_64 {
  magic: Uint32;
  cpu_type_t: cpu_type_t;
  cpu_subtype_t: cpu_subtype_t;
  filetype: Uint32;
  ncmds: Uint32;
  sizeofcmds: Uint32;
  flags: Uint32;
  reserved: Uint32;
}

interface MachoInfo {
  commonName: string;
  entitlements: string;
  certificate: string;
  icon: Promise<Blob>;
  infoPlist: {};
}

interface BlobIndex {
  type: Uint32;
  offset: Uint32 /* relative to blob offset */;
}

interface CS_SuperBlob {
  magic: Uint32;
  length: Uint32;
  count: Uint32;
  index: BlobIndex[];
}

interface linkedit_data_command {
  // p.s using this to substitute load_command struct
  cmd: Uint32;
  cmdsize: Uint32;
  dataoff: Uint32;
  datasize: Uint32;
}

/* Converts bytes to given interface.
 * @param arg Buffer to read from.
 * @param type Type to cast buffer as.
 * @return popullated interface.
 */
function interfaceCast<T>(
  arg: DataView,
  offset: number,
  interfaceType: T,
  swap: boolean
): T {
  var struct = interfaceType;
  var currentOffset: number = offset;

  Object.keys(interfaceType).forEach((key) => {
    if (key == "index") {
      console.log("[ALERT] Handling arrays manually...");
      return;
    } // skip over arrays we handle this manually for now xD

    struct[key] = swap
      ? SWAP(arg.getUint32(currentOffset))
      : arg.getUint32(currentOffset);

    const numBytes = 4; // assuming for now that all interfaces passed in are uint32's ->  theoretically this could calcuate bytes Math.round(Math.log(struct[key]) / (8 * Math.log(2)));
    currentOffset += numBytes;
  });

  return struct;
}

/* Swaps endianess
 * @param bytes The bytes to SWAP
 * @return The swapped bytes
 */
function SWAP(val: number): number {
  return (
    ((val & 0xff) << 24) |
    ((val & 0xff00) << 8) |
    ((val >> 8) & 0xff00) |
    ((val >> 24) & 0xff)
  );
  // var string = bytes.toString(16);
  // const result = [];
  // let len = string.length - 2;
  // while (len >= 0) {
  //   result.push(string.substr(len, 2));
  //   len -= 2;
  // }
  // return +("0x" + result.join(""));
}

const getZipInfo = async (file: Blob): Promise<MachoInfo> => {
  return new Promise<MachoInfo>((resolve, reject) => {
    const zipReader = new zip.ZipReader(new zip.BlobReader(file));
    zipReader
      .getEntries()
      .then((entries) => {
        // Check if Payload folder exists and it has .app folder
        let appFolder: string = null;
        for (let entry of entries) {
          if (entry.filename.endsWith(".app/", entry.filename.length)) {
            appFolder = entry.filename;
            break;
          }
        }

        if (appFolder == null) {
          reject("Malformed IPA");
          return undefined;
        }

        var entry = entries.find(
          (entry) => entry.filename == appFolder + "Info.plist"
        );

        if (entry == undefined) {
          reject("Missing Info.Plist");
          return undefined;
        }

        entry
          .getData(new zip.BlobWriter(zip.getMimeType(entry.filename)))
          .then((plistData: Blob) => {
            return plistData.arrayBuffer();
          })
          .then((plistBuffer) => {
            const plist = bplist.plistParse(plistBuffer);
            const executable: string = plist.CFBundleExecutable;
            entry = entries.find(
              (entry) => entry.filename == appFolder + executable
            );
            var icons: string[] =
              plist.CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconFiles;
            if (!icons) {
              icons = ["Icon"];
            }

            if (entry == undefined) {
              reject("Missing Binary");
              return undefined;
            }

            entry
              .getData(new zip.BlobWriter())
              .then((binary: Blob) => {
                return getInfo(binary);
              })
              .then((macho) => {
                macho.infoPlist = plist;
                macho.icon = entries
                  .find((entry) =>
                    entry.filename.startsWith(
                      appFolder + icons[icons.length - 1]
                    )
                  )
                  .getData(new zip.BlobWriter(zip.getMimeType(entry.filename)));
                resolve(macho);
              });
            zipReader.close();
          });
      })
      .catch((reason) => reject(reason));
  });
};

const readableEntitlements = (entitlements: string): string[] => {
  let types = {
    CarPlay: "com.apple.developer.carplay",
    Contacts: "com.apple.developer.contacts",
    "Exposure Notifications": "com.apple.developer.exposure-notification",
    "Game Center": "com.apple.developer.game-center",
    "Group Activities": "com.apple.developer.group-session",
    "Health Services": "com.apple.developer.healthkit",
    "Home Automation": "com.apple.developer.homekit",
    "iCloud Services": "com.apple.developer.icloud",
    "Networking Services": "com.apple.developer.networking",
    "Push Notifications": "aps-environment",
    Sensors: "com.apple.developer.sensorkit.reader.allow",
    Siri: "com.apple.developer.siri",
    ClassKit: "com.apple.developer.ClassKit-environment",
    "SignIn with Apple": "com.apple.developer.applesignin",
    AutoFill:
      "com.apple.developer.authentication-services.autofill-credential-provider",
  };

  var features: string[] = [];
  Object.entries(types).forEach((pair) => {
    if (entitlements.includes(pair[1])) {
      features.push(pair[0]);
    }
  });
  return features;
};

const getInfo = async (file: Blob): Promise<MachoInfo> => {
  if (new DataView(await file.slice(0, 4).arrayBuffer()).getUint8(0) == 80) {
    // Parse ZIP (quick check if it has the local file header signature magic)
    return getZipInfo(file);
  }

  return new Promise<MachoInfo>((resolve, reject) => {
    let reader = new FileReader();
    reader.readAsArrayBuffer(file);
    reader.onload = (e) => {
      var info: MachoInfo = {
        commonName: "NULL",
        entitlements: "NULL",
        certificate: "NULL",
        icon: Promise.reject("No Icon"),
        infoPlist: {},
      };

      var buffer = e.target.result as ArrayBuffer;
      let dv = new DataView(buffer);

      const magic = dv.getUint32(0);
      if (magic == 0xcafebabe || magic == 0xbebafeca) {
        // handle FAT binaries...
        const offset = 8; // skip over fat header (2 * 4 = 8)
        const start = dv.getUint32(offset + 8, false);
        getInfo(
          file.slice(start, dv.getUint32(offset + 8 + 4, false) + start)
        ).then((info) => {
          resolve(info);
        });
        return;
      }

      var ma: mach_header_64 = {
        magic: new Uint32(),
        cpu_type_t: new Uint32(),
        cpu_subtype_t: new Uint32(),
        filetype: new Uint32(),
        ncmds: new Uint32(),
        sizeofcmds: new Uint32(),
        flags: new Uint32(),
        reserved: new Uint32(),
      };

      var requiresSwap = true; // (ma.magic as unknown as number) == 0xcffaedfe
      ma = interfaceCast(dv, 0, ma, requiresSwap);
      var offset = 32; // size of mach_header_64 !
      for (let i = 0; i < (ma.ncmds as unknown as number); i++) {
        var lc: linkedit_data_command = {
          cmd: new Uint32(),
          cmdsize: new Uint32(),
          dataoff: new Uint32(),
          datasize: new Uint32(),
        };

        lc = interfaceCast(dv, offset, lc, requiresSwap);

        if ((lc.cmd as unknown as number) == 0x1d) {
          console.log(
            `\n\n----LC_CODE_SIGNATURE----\ncommand [${i}]\ncmdsize: ${
              lc.cmdsize as unknown as number
            }\ndataoff: 0x${(lc.dataoff as unknown as number).toString(
              16
            )}\ndatasize: ${lc.datasize as unknown as number}\n----STOP----\n\n`
          );

          var sb: CS_SuperBlob = {
            magic: new Uint32(),
            length: new Uint32(),
            count: new Uint32(),
            index: [],
          };

          var dataStart = new DataView(
            buffer.slice(
              lc.dataoff as unknown as number,
              (lc.dataoff as unknown as number) +
                (lc.datasize as unknown as number) +
                1
            )
          );

          sb = interfaceCast(dataStart, 0, sb, !requiresSwap);
          if (
            /*(sb.magic as unknown as number)*/ (sb.magic as unknown as number) !=
            0xfade0cc0
          ) {
            console.log("[ALERT] SIGNATURE EXTERNAL FROM BINARY !");
            return;
          }

          var sbOffset = 4 * 3;
          for (let m = 0; m < (sb.count as unknown as number); m++) {
            // Blobs reverse the endianness so use '!requiresSwap' when casting...
            var blobIndex: BlobIndex = {
              type: new Uint32(),
              offset: new Uint32(),
            };
            blobIndex = interfaceCast(
              dataStart,
              sbOffset,
              blobIndex,
              !requiresSwap
            );

            const blobBytes = dataStart.buffer.slice(
              blobIndex.offset as unknown as number,
              (sb.length as unknown as number) + 1
            );
            const blobMagic = dataStart.getUint32(
              blobIndex.offset as unknown as number
            );
            const blobLength = dataStart.getUint32(
              (blobIndex.offset as unknown as number) + 4
            );

            if ((blobMagic as unknown as number) == 0xfade0b01) {
              console.log("[Alert] Found CMS Blob !");
              const pkcs7Bytes = blobBytes.slice(8, blobLength);

              var pem = derToPem(pkcs7Bytes);
              var cert = forge.pkcs7.messageFromPem(
                pem
              ) as unknown as forge.pkcs7.PkcsSignedData;
              info.commonName =
                cert.certificates[2].subject.getField("CN").value;
              info.certificate = forge.pki.certificateToPem(
                cert.certificates[2]
              );
            } else if ((blobMagic as unknown as number) == 0xfade7171) {
              // This blob contains entitlements :D
              var enc = new TextDecoder("utf-8");
              info.entitlements = enc.decode(blobBytes.slice(8, blobLength));
            }

            sbOffset += 4 * 2;
          }
          break;
        }

        offset += lc.cmdsize as unknown as number; // should always be 16 bytes, but whatever
      }
      resolve(info);
    };
  });
};

function _arrayBufferToBase64(buffer: ArrayBuffer): string {
  var binary = "";
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary); //.replace(/(.{64})/g, "$1\n"); // classic 64 character spacing for base64 encoding...
}

function derToPem(buffer: ArrayBuffer): string {
  // forcibly converts der content to pem format
  var base64 = _arrayBufferToBase64(buffer).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PKCS7-----\n${base64}\n-----END PKCS7-----\n`;
}

function save(filename: string, data: any) {
  const blob = new Blob([data], { type: "application/octet-stream" });
  const elem = window.document.createElement("a");
  elem.href = window.URL.createObjectURL(blob);
  elem.download = filename;
  document.body.appendChild(elem);
  elem.click();
  document.body.removeChild(elem);
}

export { getInfo, readableEntitlements, save };
export type { MachoInfo };
