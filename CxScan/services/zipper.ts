import * as fs from 'fs';
import archiver from 'archiver';
import {Logger} from "./logger";
import {walk} from "walk";
import * as path from "path";
import {FilenameFilter} from "../dto/filenameFilter";
import * as micromatch from "micromatch";

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

    private archive: archiver.Archiver | undefined;

    private srcDir: string = '';

    private filenameFilter: FilenameFilter | undefined;

    constructor(private readonly log: Logger) {
    }

    zipDirectory(srcDir: string, targetPath: string, foldersToExclude: string[], filter: FilenameFilter): Promise<any> {
        this.srcDir = srcDir;
        this.filenameFilter = filter;

        return new Promise<any>((resolve, reject) => {
            // Prepare the archiver.
            this.archive = archiver('zip', {zlib: {level: 9}});

            this.archive.on('warning', (err: any) => {
                this.log.info(`Archiver:: WARN ${err}`);
            });

            this.archive.on('error', (err: any, reject: any) => {
                this.log.info(`Archiver:: ERROR ${err}`);
                reject(err);
            });

            // Prepare output stream for the archive.
            const zipOutput = fs.createWriteStream(targetPath);
            zipOutput.on('close', () => this.onArchiveCreated(targetPath, reject, resolve));
            this.archive.pipe(zipOutput);

            this.log.debug('Scanning source directory.');
            // followLinks is set to true to conform to Common Client behavior.
            const walker = walk(this.srcDir, {filters: foldersToExclude, followLinks: true});

            walker.on('file', this.addFileToArchive);

            walker.on('end', () => {
                this.log.debug('Finished scanning source directory.');
                (this.archive as archiver.Archiver).finalize();
            });
        });
    }

    private addFileToArchive = (parentDir: string, fileStats: any, discoverNextFile: () => void) => {
        const srcFilePath = path.resolve(parentDir, fileStats.name);
        if (this.passesFilter(fileStats.name)) {
            this.log.debug(` Add: ${srcFilePath}`);
            const directoryInArchive = path.relative(this.srcDir, parentDir);

            (this.archive as archiver.Archiver).file(srcFilePath, {
                name: fileStats.name,
                prefix: directoryInArchive
            });
        } else {
            this.log.debug(`Skip: ${srcFilePath}`);
        }
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