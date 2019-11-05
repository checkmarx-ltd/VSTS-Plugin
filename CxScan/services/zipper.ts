import * as fs from 'fs';
import archiver, {Archiver, ArchiverError, ProgressData} from 'archiver';
import {Logger} from "./logger";
import {walk} from "walk";
import * as path from "path";
import {FilenameFilter} from "../dto/filenameFilter";
import * as micromatch from "micromatch";
import {ZipResult} from "../dto/zipResult";

export default class Zipper {
    private static readonly fileMatcherOptions = {
        dot: true,   // Match dotfiles.
        // Disable extended functionality that we don't expect in a file filter.
        nobrace: true,
        nobracket: true,
        noextglob: true,
        noglobstar: true,
        noquantifiers: true
    };

    private archiver: Archiver | undefined;

    private srcDir: string = '';

    private filenameFilter: FilenameFilter | undefined;

    private totalAddedFiles = 0;

    constructor(private readonly log: Logger) {
    }

    zipDirectory(srcDir: string, targetPath: string, foldersToExclude: string[], filter: FilenameFilter): Promise<ZipResult> {
        this.srcDir = srcDir;
        this.filenameFilter = filter;
        this.totalAddedFiles = 0;

        return new Promise<ZipResult>((resolve, reject) => {
            this.archiver = this.createArchiver(reject);
            const zipOutput = this.createOutputStream(targetPath, resolve);
            this.archiver.pipe(zipOutput);

            this.log.debug('Discovering files in source directory.');
            // followLinks is set to true to conform to Common Client behavior.
            const walker = walk(this.srcDir, {filters: foldersToExclude, followLinks: true});

            walker.on('file', this.addFileToArchive);

            walker.on('end', () => {
                this.log.debug('Finished discovering files in source directory.');
                (this.archiver as Archiver).finalize();
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

            const archiver = this.archiver as Archiver;

            this.log.info(`Acrhive creation completed. Total bytes written: ${archiver.pointer()}, files: ${this.totalAddedFiles}.`);
            resolve(zipResult);
        });
        return result;
    }

    private addFileToArchive = (parentDir: string, fileStats: any, discoverNextFile: () => void) => {
        const srcFilePath = path.resolve(parentDir, fileStats.name);
        if (this.passesFilter(fileStats.name)) {
            this.log.debug(` Add: ${srcFilePath}`);
            const directoryInArchive = path.relative(this.srcDir, parentDir);

            (this.archiver as Archiver).file(srcFilePath, {
                name: fileStats.name,
                prefix: directoryInArchive
            });
        } else {
            this.log.debug(`Skip: ${srcFilePath}`);
        }

        discoverNextFile();
    };

    private passesFilter(filename: string) {
        let result = true;
        if (this.filenameFilter) {
            const matchesAnyInclusionPattern = micromatch.any(filename, this.filenameFilter.include, Zipper.fileMatcherOptions);
            const matchesAnyExclusionPattern = micromatch.any(filename, this.filenameFilter.exclude, Zipper.fileMatcherOptions);
            result = matchesAnyInclusionPattern && !matchesAnyExclusionPattern;
        }
        return result;
    }
}