import * as forge from "node-forge";
import * as zip from "@zip.js/zip.js"; // efficient framework for unzipping | lists entries first instead of extracting all |
import * as bplist from "./bplist-parse";
// import * as ocsp from "./ocsp.bundle";
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

                // macho.icon = entries
                //   .find(
                //     (entry) =>
                //       icons.includes(entry.filename.at(appFolder.length))
                //   )
                //   .getData(new zip.BlobWriter(zip.getMimeType(entry.filename)))
                //   .then((iconData: Blob) => {
                //     return iconData;
                //   });

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
        icon: null,
        infoPlist: {},
      };

      var buffer = e.target.result as ArrayBuffer;
      let dv = new DataView(buffer);

      var ma: mach_header_64 = {
        magic: new Uint32(),
        cpu_type_t: new Uint32(),
        cpu_subtype_t: new Uint32(),
        filetype: new Uint32(),
        ncmds: new Uint32(),
        sizeofcmds: new Uint32(),
        flags: new Uint32(),
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
              //               const issuer = `-----BEGIN CERTIFICATE-----
              // MIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE
              // BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp
              // ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTEz
              // MDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVTMRMwEQYD
              // VQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
              // cGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3Bl
              // ciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3
              // DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0U3rOfGOA
              // YXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkVCBmsqtsq
              // Mu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8V25nNYB2
              // NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHld0WNUEi6
              // Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1qarunFjVg
              // 0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGjgaYwgaMw
              // HQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQFMAMBAf8w
              // HwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcwJTAjoCGg
              // H4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgGG
              // MBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Zviz1smwv
              // j+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/Nw0Uwj6OD
              // Dc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJTleMa1s8
              // Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1VAKmuu0sw
              // ruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur+cmV6U/k
              // TecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxRpVzscYqC
              // tGwPDBUf
              // -----END CERTIFICATE-----
              // -----BEGIN CERTIFICATE-----
              // MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
              // MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
              // biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
              // MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
              // bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
              // FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
              // ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
              // +FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
              // XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
              // tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
              // q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
              // aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
              // BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
              // R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
              // ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
              // d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
              // IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
              // YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
              // b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
              // Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
              // NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
              // y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
              // R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
              // xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
              // IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
              // UKqK1drk/NAJBzewdXUh
              // -----END CERTIFICATE-----
              // -----BEGIN CERTIFICATE-----
              // MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi
              // MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw
              // bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg
              // Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB
              // cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u
              // IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ
              // BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ
              // C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW
              // BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj
              // +ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b
              // 5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A
              // 0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS
              // VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
              // BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG
              // AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh
              // MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js
              // MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw
              // EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH
              // Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA
              // HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK
              // XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7
              // bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC
              // NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza
              // UDSdlTs=
              // -----END CERTIFICATE-----`;
              // console.log(issuer);
              // console.log(ocsp.check(info.certificate, issuer));

              // check(
              //   {
              //     cert: info.certificate,
              //     issuer: forge.pki.certificateToPem(cert.certificates[1]),
              //   },
              //   function (err, res) {
              //     if (err) {
              //       console.error(err);
              //     }
              //     console.log(res);
              //   }
              // );
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
