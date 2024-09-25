>OpenAPI Parser
>- Parses OpenAPI Documentation

> JS Link Finder
> - Looks in JavaScript files for API endpoints

>Content-Type Converter
>- automatically convert data submitted within requests between XML and JSON.

> Param miner
> - automatically guess up to 65,536 param names per request

- `PATCH` - Applies partial changes to a resource.
- `OPTIONS` - Retrieves information on the types of request methods that can be used on
#### Checklist
- Hidden parameters
- Mass assignment
- HTTP (server-side) parameter pollution
	- Test by: Overriding, Injecting valid/non-valid params
	- Input: `# or %23, & or %26, and =`
		- #=truncate
	- Ex:
		- ``GET /userSearch?name=peter%23foo&back=/home``
		
	