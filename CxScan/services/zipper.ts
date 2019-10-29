import * as fs from 'fs';
import archiver from 'archiver';
import {Logger} from "./logger";

export default class Zipper {
    constructor(private readonly log: Logger) {
    }

    async zipDirectory(srcDir: string, targetPath: string): Promise<any> {
        try {
            return new Promise<any>((resolve, reject) => {
                const zipOutput = fs.createWriteStream(targetPath);
                const archive = archiver('zip', {zlib: {level: 9}});

                archive.on('warning', (err: any) => {
                    if (err.code === 'ENOENT') {
                        this.log.info(err);
                    } else {
                        throw err;
                    }
                });

                archive.on('error', (err: any) => {
                    throw err;
                });

                zipOutput.on('close', () => {
                    this.log.info('Archiver:: INFO ' + archive.pointer() + ' total bytes');
                    this.log.info('Archiver:: INFO Archiver has been finalized and the output file descriptor has closed.');
                    fs.readFile(targetPath, 'base64', err => {
                        if (err) {
                            this.log.info('Archiver:: ZipFile fs.readFile ERROR ' + err);
                            reject(err);
                        } else {
                            resolve();
                        }
                    });
                });

                archive.on('error', err => {
                    this.log.info('Archiver:: ERROR ' + err);
                    reject(err);
                });
                archive.pipe(zipOutput);
                archive.directory(srcDir, false);
                archive.finalize();
            });
        } catch (err) {
            this.log.info('Archiver:: zipDirectory() ERROR ' + err);
        }
    }
}