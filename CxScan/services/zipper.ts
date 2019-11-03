import * as fs from 'fs';
import archiver from 'archiver';
import {Logger} from "./logger";
import {walk} from "walk";
import * as path from "path";

export default class Zipper {
    private archive: archiver.Archiver | undefined;
    private srcDir: string = '';

    constructor(private readonly log: Logger) {
    }

    zipDirectory(srcDir: string, targetPath: string, foldersToExclude: string[]): Promise<any> {
        this.srcDir = srcDir;

        return new Promise<any>((resolve, reject) => {
            this.archive = archiver('zip', {zlib: {level: 9}});

            this.archive.on('warning', (err: any) => {
                this.log.info(`Archiver:: WARN ${err}`);
            });

            this.archive.on('error', (err: any, reject: any) => {
                this.log.info('Archiver:: ERROR ' + err);
                reject(err);
            });

            const zipOutput = fs.createWriteStream(targetPath);
            zipOutput.on('close', () => this.onArchiveCreated(targetPath, reject, resolve));
            this.archive.pipe(zipOutput);

            this.log.debug('Scanning source directory.');
            // followLinks is set to true to conform to Common Client behavior.
            const walker = walk(srcDir, {filters: foldersToExclude, followLinks: true});

            walker.on('file', this.addFileToArchive);

            walker.on('end', () => {
                this.log.debug('Finished scanning source directory.');
                (this.archive as archiver.Archiver).finalize();
            });
        });
    }

    private addFileToArchive = (parentDir: string, fileStats: any, discoverNextFile: () => void) => {
        const srcFilePath = path.resolve(parentDir, fileStats.name);
        const directoryInArchive = path.relative(this.srcDir, parentDir);
        this.log.debug(`Adding file to archive: ${srcFilePath}`);

        (this.archive as archiver.Archiver).file(srcFilePath, {
            name: fileStats.name,
            prefix: directoryInArchive
        });

        discoverNextFile();
    };

    private onArchiveCreated = (targetPath: string,
                                reject: (reason: any) => void,
                                resolve: () => void) => {
        const archive = this.archive as archiver.Archiver;
        this.log.info(`Archiver:: INFO ${archive.pointer()} total bytes`);
        this.log.info('Archiver:: INFO Archiver has been finalized and the output file descriptor has closed.');
        this.verifyArchiveCreated(targetPath, reject, resolve);
    };

    private verifyArchiveCreated(targetPath: string, reject: (reason: any) => void, resolve: () => void) {
        fs.readFile(targetPath, null, err => {
            if (err) {
                this.log.info(`Archiver:: ZipFile fs.readFile ERROR ${err}`);
                reject(err);
            } else {
                resolve();
            }
        });
    }
}