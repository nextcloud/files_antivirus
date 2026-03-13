<?php

/**
 * SPDX-FileCopyrightText: 2016-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
namespace OCA\DAV\Upload;

use OCA\DAV\Connector\Sabre\Directory;
use Sabre\DAV\Exception\Forbidden;
use Sabre\DAV\IFile;

/**
 * Class FutureFile
 *
 * The FutureFile is a SabreDav IFile which connects the chunked upload directory
 * with the AssemblyStream, who does the final assembly job
 *
 * @package OCA\DAV\Upload
 */
class FutureFile implements \Sabre\DAV\IFile {
	/**
	 * @param Directory $root
	 * @param string $name
	 */
	public function __construct(
		private Directory $root,
		private $name,
	) {
	}

	/**
	 * @inheritdoc
	 */
	public function put($data)
    {
    }

	/**
	 * @inheritdoc
	 */
	public function get()
    {
    }

	public function getPath()
    {
    }

	/**
	 * @inheritdoc
	 */
	public function getContentType()
    {
    }

	/**
	 * @inheritdoc
	 */
	public function getETag()
    {
    }

	/**
	 * @inheritdoc
	 */
	public function getSize()
    {
    }

	/**
	 * @inheritdoc
	 */
	public function delete()
    {
    }

	/**
	 * @inheritdoc
	 */
	public function getName()
    {
    }

	/**
	 * @inheritdoc
	 */
	public function setName($name)
    {
    }

	/**
	 * @inheritdoc
	 */
	public function getLastModified()
    {
    }
}
