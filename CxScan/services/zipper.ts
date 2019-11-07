import * as fs from 'fs';
import archiver, {Archiver, ArchiverError, ProgressData} from 'archiver';
import {Logger} from "./logger";
import {walk} from "walk";
import {FilePathFilter} from "./filePathFilter";
import {ZipResult} from "../dto/zipResult";
import * as upath from 'upath';

export default class Zipper {
    private archiver!: Archiver;

    private srcDir: string = '';

    private totalAddedFiles = 0;

    constructor(private readonly log: Logger,
                private readonly filenameFilter: FilePathFilter) {
    }

    zipDirectory(srcDir: string, targetPath: string): Promise<ZipResult> {
        this.srcDir = srcDir;
        this.totalAddedFiles = 0;

        return new Promise<ZipResult>((resolve, reject) => {
            this.archiver = this.createArchiver(reject);
            const zipOutput = this.createOutputStream(targetPath, resolve);
            this.archiver.pipe(zipOutput);

            this.log.debug('Discovering files in source directory.');
            // followLinks is set to true to conform to Common Client behavior.
            const walker = walk(this.srcDir, {followLinks: true});

            walker.on('file', this.addFileToArchive);

            walker.on('end', () => {
                this.log.debug('Finished discovering files in source directory.');
                this.archiver.finalize();
            });
        });
    }

    private createArchiver(reject: any) {
        const result = archiver('zip', {zlib: {level: 9}});

        result.on('warning', (err: ArchiverError) => {
            this.log.warning(`Archiver: ${err.message}`);
        });

        result.on('error', (err: ArchiverError) => {
            reject(err);
        });

        result.on('progress', (data: ProgressData) => {
            this.totalAddedFiles = data.entries.processed;
        });
        return result;
    }

    private createOutputStream(targetPath: string, resolve: (value: ZipResult) => void) {
        const result = fs.createWriteStream(targetPath);
        result.on('close', () => {
            const zipResult: ZipResult = {
                fileCount: this.totalAddedFiles
            };

            this.log.info(`Acrhive creation completed. Total bytes written: ${this.archiver.pointer()}, files: ${this.totalAddedFiles}.`);
            resolve(zipResult);
        });
        return result;
    }

    private addFileToArchive = (parentDir: string, fileStats: any, discoverNextFile: () => void) => {
        const absoluteFilePath = upath.resolve(parentDir, fileStats.name);
        const relativeFilePath = upath.relative(this.srcDir, absoluteFilePath);

        // relativeFilePath is normalized to contain forward slashes independent of the current OS. Examples:
        //      page.cs                             - if page.cs is at the project's root dir
        //      services/internal/myservice.js      - if myservice.js is in a nested dir
        if (this.filenameFilter.includes(relativeFilePath)) {
            this.log.debug(` Add: ${absoluteFilePath}`);

            const relativeDirInArchive = upath.relative(this.srcDir, parentDir);
            this.archiver.file(absoluteFilePath, {
                name: fileStats.name,
                prefix: relativeDirInArchive
            });
        } else {
            this.log.debug(`Skip: ${absoluteFilePath}`);
        }

        discoverNextFile();
    };
}